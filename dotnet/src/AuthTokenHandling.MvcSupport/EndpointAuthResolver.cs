#if !NET46

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Result of the UC-4 endpoint resolution: how a controller action wants to be authenticated.
  /// </summary>
  public sealed class EndpointAuthInfo {

    private bool _IsAnonymous;
    private string[] _LogicalNames;
    private string[] _TokenSourceIds;
    private string[] _RequiredScopes;

    /// <summary>
    /// Creates a new instance (null arrays are replaced by empty arrays).
    /// </summary>
    public EndpointAuthInfo(bool isAnonymous, string[] logicalNames, string[] tokenSourceIds, string[] requiredScopes) {
      _IsAnonymous = isAnonymous;
      _LogicalNames = EnsureArray(logicalNames);
      _TokenSourceIds = EnsureArray(tokenSourceIds);
      _RequiredScopes = EnsureArray(requiredScopes);
    }

    /// <summary>
    /// true, if no token (and no scope) is required: 'AuthTokenSourceAttribute(null)' or any logical name of the
    /// endpoint was registered via 'AccessTokenManager.MapAnonymous'.
    /// NOTE: '[AllowAnonymous]' is NOT evaluated, because UJMW may emit it for controllers whose authentication is
    /// done by its own hook.
    /// </summary>
    public bool IsAnonymous {
      get {
        return _IsAnonymous;
      }
    }

    /// <summary>
    /// All logical names of the endpoint in chain order (AuthTokenSourceAttribute, API group, schemes, policies).
    /// </summary>
    public string[] LogicalNames {
      get {
        return _LogicalNames;
      }
    }

    /// <summary>
    /// The registered token sources (in mapping order, the first one is the primary). Empty = fail closed.
    /// </summary>
    public string[] TokenSourceIds {
      get {
        return _TokenSourceIds;
      }
    }

    /// <summary>
    /// The accumulated (AND) required scopes, already prefixed with the configured API permission prefix.
    /// </summary>
    public string[] RequiredScopes {
      get {
        return _RequiredScopes;
      }
    }

    private static string[] EnsureArray(string[] values) {
      if (values == null) {
        return new string[] { };
      }
      return values;
    }

  }

  /// <summary>
  /// UC-4 resolver: determines (read-only, never intercepting the ASP.NET Core auth pipeline) how a controller
  /// action wants to be authenticated. Resolution order:
  /// 1. 'AuthTokenSourceAttribute' on the controller (null = anonymous, "" = not known),
  /// 2. API group name ('[ApiExplorerSettings(GroupName)]' of action or controller),
  /// 3. authentication scheme(s) from '[Authorize]' ([policy -&gt;] scheme, falling back to the default policy
  ///    and finally to the default authenticate scheme), followed by the policy names.
  /// </summary>
  public static class EndpointAuthResolver {

    /// <summary>
    /// Resolves the authentication information of the given action
    /// (async, because the ASP.NET Core policy resolution is async).
    /// </summary>
    /// <param name="action">The action to evaluate.</param>
    /// <param name="services">Used to obtain 'IAuthorizationPolicyProvider' and 'IAuthenticationSchemeProvider' (optional).</param>
    public static async Task<EndpointAuthInfo> ResolveEndpointAuthAsync(ActionDescriptor action, IServiceProvider services) {
      if (action == null) {
        throw new ArgumentNullException(nameof(action));
      }

      List<string> logicalNames = new List<string>();
      ControllerActionDescriptor controllerAction = action as ControllerActionDescriptor;

      //1. AuthTokenSourceAttribute on the controller
      if (controllerAction != null) {
        string attributeValue;
        if (AuthTokenSourceAttribute.TryPickFrom(controllerAction.ControllerTypeInfo.AsType(), out attributeValue)) {
          if (attributeValue == null) {
            return new EndpointAuthInfo(true, new string[] { }, new string[] { }, new string[] { });
          }
          if (attributeValue.Length > 0) {
            AddDistinct(logicalNames, attributeValue);
          }
        }
      }

      //2. API group name
      AddDistinct(logicalNames, GetApiGroupName(action));

      //3. schemes (and policies) from [Authorize]
      string[] schemeAndPolicyNames = await ResolveAuthenticationSchemeNamesAsync(action, services);
      foreach (string name in schemeAndPolicyNames) {
        AddDistinct(logicalNames, name);
      }

      string[] names = logicalNames.ToArray();
      if (AccessTokenManager.IsAnonymous(names)) {
        return new EndpointAuthInfo(true, names, new string[] { }, new string[] { });
      }

      List<string> requiredScopes = new List<string>(AccessTokenManager.GetRequiredScopes(names));
      foreach (string scope in GetLegacyRequiredApiPermissions(controllerAction)) {
        AddDistinct(requiredScopes, AccessTokenManager.ApplyApiPermissionPrefix(scope));
      }

      string[] tokenSourceIds = AccessTokenManager.ResolveRegisteredTokenSourceIdsForChain(names);
      return new EndpointAuthInfo(false, names, tokenSourceIds, requiredScopes.ToArray());
    }

    /// <summary>
    /// Returns the authentication scheme names (followed by the policy names) declared via '[Authorize]' on the
    /// action or its controller. Policies are resolved via 'IAuthorizationPolicyProvider'; if '[Authorize]' names
    /// neither schemes nor a policy with schemes, the default policy and finally the default authenticate scheme
    /// ('IAuthenticationSchemeProvider') are used. Returns an empty array if no '[Authorize]' is present.
    /// </summary>
    public static async Task<string[]> ResolveAuthenticationSchemeNamesAsync(ActionDescriptor action, IServiceProvider services) {
      List<string> schemeNames = new List<string>();
      List<string> policyNames = new List<string>();

      IAuthorizeData[] authorizeData = GetAuthorizeData(action);
      if (authorizeData.Length == 0) {
        return new string[] { };
      }

      IAuthorizationPolicyProvider policyProvider = null;
      IAuthenticationSchemeProvider schemeProvider = null;
      if (services != null) {
        policyProvider = (IAuthorizationPolicyProvider)services.GetService(typeof(IAuthorizationPolicyProvider));
        schemeProvider = (IAuthenticationSchemeProvider)services.GetService(typeof(IAuthenticationSchemeProvider));
      }

      foreach (IAuthorizeData data in authorizeData) {
        AddSchemeList(schemeNames, data.AuthenticationSchemes);
        if (!string.IsNullOrWhiteSpace(data.Policy)) {
          AddDistinct(policyNames, data.Policy.Trim());
          if (policyProvider != null) {
            AuthorizationPolicy policy = await policyProvider.GetPolicyAsync(data.Policy);
            if (policy != null) {
              foreach (string scheme in policy.AuthenticationSchemes) {
                AddDistinct(schemeNames, scheme);
              }
            }
          }
        }
      }

      if (schemeNames.Count == 0 && policyProvider != null) {
        AuthorizationPolicy defaultPolicy = await policyProvider.GetDefaultPolicyAsync();
        if (defaultPolicy != null) {
          foreach (string scheme in defaultPolicy.AuthenticationSchemes) {
            AddDistinct(schemeNames, scheme);
          }
        }
      }

      if (schemeNames.Count == 0 && schemeProvider != null) {
        AuthenticationScheme defaultScheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
        if (defaultScheme != null) {
          AddDistinct(schemeNames, defaultScheme.Name);
        }
      }

      foreach (string policyName in policyNames) {
        AddDistinct(schemeNames, policyName);
      }
      return schemeNames.ToArray();
    }

    /// <summary>
    /// Reads the API group name from '[ApiExplorerSettings(GroupName = ...)]' of the action or the controller.
    /// Returns "" if not known.
    /// </summary>
    public static string GetApiGroupName(ActionDescriptor action) {
      ControllerActionDescriptor controllerAction = action as ControllerActionDescriptor;
      if (controllerAction == null) {
        return string.Empty;
      }
      ApiExplorerSettingsAttribute settings = controllerAction.MethodInfo.GetCustomAttribute<ApiExplorerSettingsAttribute>(true);
      if (settings == null || string.IsNullOrEmpty(settings.GroupName)) {
        settings = controllerAction.ControllerTypeInfo.GetCustomAttribute<ApiExplorerSettingsAttribute>(true);
      }
      if (settings == null || settings.GroupName == null) {
        return string.Empty;
      }
      return settings.GroupName;
    }

    /// <summary>
    /// Collects the '[Authorize]' data of the action method and its controller.
    /// </summary>
    private static IAuthorizeData[] GetAuthorizeData(ActionDescriptor action) {
      List<IAuthorizeData> result = new List<IAuthorizeData>();
      ControllerActionDescriptor controllerAction = action as ControllerActionDescriptor;
      if (controllerAction != null) {
        result.AddRange(controllerAction.ControllerTypeInfo.GetCustomAttributes(true).OfType<IAuthorizeData>());
        result.AddRange(controllerAction.MethodInfo.GetCustomAttributes(true).OfType<IAuthorizeData>());
      }
      else if (action.EndpointMetadata != null) {
        result.AddRange(action.EndpointMetadata.OfType<IAuthorizeData>());
      }
      return result.ToArray();
    }

    /// <summary>
    /// Returns the legacy required API permissions ('RequiredApiPermissionAttribute' on the controller and
    /// 'EvaluateBearerTokenAttribute' on the action), without prefix.
    /// </summary>
    private static string[] GetLegacyRequiredApiPermissions(ControllerActionDescriptor controllerAction) {
      List<string> result = new List<string>();
      if (controllerAction == null) {
        return result.ToArray();
      }
      string[] attributeScopes;
      if (RequiredApiPermissionAttribute.TryPickFrom(controllerAction.ControllerTypeInfo.AsType(), out attributeScopes) && attributeScopes != null) {
        foreach (string scope in attributeScopes) {
          AddDistinct(result, scope);
        }
      }
      EvaluateBearerTokenAttribute evaluateAttribute = controllerAction.MethodInfo.GetCustomAttribute<EvaluateBearerTokenAttribute>(true);
      if (evaluateAttribute != null) {
        foreach (string scope in evaluateAttribute.RequiredApiPermissions) {
          AddDistinct(result, scope);
        }
      }
      return result.ToArray();
    }

    private static void AddSchemeList(List<string> target, string commaSeparatedSchemes) {
      if (string.IsNullOrWhiteSpace(commaSeparatedSchemes)) {
        return;
      }
      foreach (string scheme in commaSeparatedSchemes.Split(',')) {
        AddDistinct(target, scheme.Trim());
      }
    }

    private static void AddDistinct(List<string> target, string value) {
      if (string.IsNullOrWhiteSpace(value)) {
        return;
      }
      if (!target.Contains(value, StringComparer.OrdinalIgnoreCase)) {
        target.Add(value);
      }
    }

  }

}

#endif
