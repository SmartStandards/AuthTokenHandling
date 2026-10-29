using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    private bool TryGetPasstroughUserIdentity(out string userName) {
      userName = null;

      //if (!OperatingSystem.IsWindows()){
      //  return false;
      //}
 
      try {
        if (this.HttpContext.User.Identity is WindowsIdentity) {
          WindowsIdentity windowsUserIfIdentified = null;
          windowsUserIfIdentified = (WindowsIdentity)this.HttpContext.User.Identity!;
          userName = windowsUserIfIdentified.Name?.ToString();
        }
        else if (this.HttpContext.User.Identity is ClaimsIdentity) {
          ClaimsIdentity windowsUserIfIdentified = null;
          windowsUserIfIdentified = (ClaimsIdentity)this.HttpContext.User.Identity!;
          userName = windowsUserIfIdentified.Name?.ToString();
        }
        else {
          SecLogger.LogWarning($"Cannot identify pass-trough user identity: Unknown identity-class");
        }
        SecLogger.LogInformation($"Identified pass-trough user identity: " + userName);
      }
      catch (Exception ex) {
        SecLogger.LogWarning($"Cannot identify pass-trough user identity: " + ex.Message);
      }

      return !string.IsNullOrWhiteSpace(userName);
    }

    #region " Pass-Through Availability "

    /// <summary>
    /// The name of the (optional) host-registered authorization policy which was required by the SSO endpoints before.
    /// If registered, it is still evaluated (no breaking change).
    /// </summary>
    internal const string WindowsOnlyPolicyName = "WindowsOnly";

    /// <summary>
    /// Well-known names of Windows authentication schemes ('Negotiate': Kestrel/HttpSys, 'Windows': IIS).
    /// </summary>
    private static readonly string[] _WindowsAuthSchemeNames = new string[] { "Negotiate", "Windows" };

    /// <summary>
    /// Returns the configured pass-through mode ('Auto', if no 'CheapOAuthOptions' are registered).
    /// </summary>
    private PassThroughMode GetPassThroughMode() {
      CheapOAuthOptions options = this.HttpContext.RequestServices.GetService<CheapOAuthOptions>();
      if (options == null) {
        return PassThroughMode.Auto;
      }
      return options.EnablePassThrough;
    }

    /// <summary>
    /// Returns the name of the first registered Windows authentication scheme or null.
    /// </summary>
    private string GetWindowsAuthSchemeName() {
      IAuthenticationSchemeProvider schemeProvider = this.HttpContext.RequestServices.GetService<IAuthenticationSchemeProvider>();
      if (schemeProvider == null) {
        return null;
      }
      foreach (string schemeName in _WindowsAuthSchemeNames) {
        AuthenticationScheme scheme = schemeProvider.GetSchemeAsync(schemeName).GetAwaiter().GetResult();
        if (scheme != null) {
          return scheme.Name;
        }
      }
      return null;
    }

    /// <summary>
    /// Returns the host-registered 'WindowsOnly' policy or null (an unknown policy name does not throw here).
    /// </summary>
    private AuthorizationPolicy GetWindowsOnlyPolicy() {
      IAuthorizationPolicyProvider policyProvider = this.HttpContext.RequestServices.GetService<IAuthorizationPolicyProvider>();
      if (policyProvider == null) {
        return null;
      }
      return policyProvider.GetPolicyAsync(WindowsOnlyPolicyName).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Evaluates, whether the Windows pass-through login can be offered (depending on 'CheapOAuthOptions.EnablePassThrough').
    /// </summary>
    internal bool IsPassThroughAvailable() {
      PassThroughMode mode = this.GetPassThroughMode();
      if (mode == PassThroughMode.Off) {
        return false;
      }
      if (mode == PassThroughMode.On) {
        return true;
      }
      if (this.GetWindowsAuthSchemeName() != null) {
        return true;
      }
      return (this.GetWindowsOnlyPolicy() != null);
    }

    /// <summary>
    /// Ensures a Windows identity for the SSO endpoints (replaces the former [Authorize(Policy = "WindowsOnly")]).
    /// A host-registered 'WindowsOnly' policy is evaluated exactly like the attribute did it,
    /// otherwise the registered Windows authentication scheme is used. Instead of throwing, a missing host
    /// setup results in an error page.
    /// </summary>
    /// <param name="viewOpt">The view options for an error page.</param>
    /// <param name="winUserName">Receives the name of the Windows user.</param>
    /// <param name="alternativeResult">Receives a challenge, forbid or error result, if no identity is available.</param>
    /// <returns>True, if the Windows identity is available.</returns>
    internal bool TryEnsurePassThroughIdentity(AuthPageViewModeOptions viewOpt, out string winUserName, out ActionResult alternativeResult) {
      winUserName = null;
      alternativeResult = null;

      if (!this.IsPassThroughAvailable()) {
        alternativeResult = this.Content(
          _AuthPageBuilder.GetErrorPage("Single-Sign-On (pass-through) is not available on this server!", viewOpt), "text/html"
        );
        return false;
      }

      string challengeScheme = null;

      AuthorizationPolicy policy = this.GetWindowsOnlyPolicy();
      IPolicyEvaluator policyEvaluator = this.HttpContext.RequestServices.GetService<IPolicyEvaluator>();
      if (policy != null && policyEvaluator != null) {
        AuthenticateResult authenticateResult = policyEvaluator.AuthenticateAsync(policy, this.HttpContext).GetAwaiter().GetResult();
        PolicyAuthorizationResult authorizeResult = policyEvaluator.AuthorizeAsync(
          policy, authenticateResult, this.HttpContext, null
        ).GetAwaiter().GetResult();
        if (authorizeResult.Challenged) {
          alternativeResult = this.Challenge(policy.AuthenticationSchemes.ToArray());
          return false;
        }
        if (authorizeResult.Forbidden) {
          alternativeResult = this.Forbid(policy.AuthenticationSchemes.ToArray());
          return false;
        }
      }
      else {
        challengeScheme = this.GetWindowsAuthSchemeName();
        if (challengeScheme != null && !this.TryGetPasstroughUserIdentity(out winUserName)) {
          AuthenticateResult authenticateResult = this.HttpContext.AuthenticateAsync(challengeScheme).GetAwaiter().GetResult();
          if (authenticateResult.Succeeded) {
            this.HttpContext.User = authenticateResult.Principal;
          }
        }
      }

      if (this.TryGetPasstroughUserIdentity(out winUserName)) {
        return true;
      }

      if (challengeScheme == null) {
        challengeScheme = this.GetWindowsAuthSchemeName();
      }
      if (challengeScheme == null) {
        alternativeResult = this.Content(
          _AuthPageBuilder.GetErrorPage("Single-Sign-On (pass-through) is enabled, but the host has no Windows authentication configured!", viewOpt), "text/html"
        );
        return false;
      }

      alternativeResult = this.Challenge(challengeScheme);
      return false;
    }

    #endregion

  }

  internal static class UrlHelperExtension {


    public static string SetQueryParam(this string url, string name, string value, bool urlEncode = false) {
      if (urlEncode || value.Contains("&")) {
        value = HttpUtility.UrlEncode(value);
      }
      if (url.Contains("?")) {
        int idx = url.IndexOf("?");
        string[] kvps = url.Substring(idx + 1).Split('&');
        for(int i=0; i<kvps.Length; i++) {
          string kvp = kvps[i];
          if (kvp.StartsWith($"{name}=")) {
            kvps[i] = $"{name}={value}";
            return $"{url.Substring(0, idx + 1)}{string.Join("&", kvps)}";
          }
        }
        return $"{url}&{name}={value}";
      }
      else {
        return $"{url}?{name}={value}";
      }
    }

    public static string AppendQueryParam(this string url, string name, string value, bool urlEncode = false) {
      if (urlEncode) {
        value = HttpUtility.UrlEncode(value);
      }
      if (url.Contains("?")) {
        return $"{url}&{name}={value}";
      }
      else {
        return $"{url}?{name}={value}";
      }
    }

  }

}
