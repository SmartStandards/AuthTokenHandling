#if !NET46

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using static System.Formats.Asn1.AsnWriter;

namespace Security.AccessTokenHandling {

  [AttributeUsage(validOn: AttributeTargets.Method)]
  public class EvaluateBearerTokenAttribute : Attribute, IAsyncActionFilter {

    private string[] _RequiredApiPermissions;

    public EvaluateBearerTokenAttribute(params string[] requiredApiPermissions) {
      _RequiredApiPermissions = requiredApiPermissions;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next) {
      
      try {

        string rawToken = null;
        if (context.HttpContext.Request.Headers.TryGetValue("Authorization", out var extractedAuthHeader)) {  
          rawToken = extractedAuthHeader.ToString();
          if (String.IsNullOrWhiteSpace(rawToken)) {
            rawToken = null;
          }
          else if (rawToken.StartsWith("Bearer ",StringComparison.CurrentCultureIgnoreCase)) {
            rawToken = rawToken.Substring(7);
          }
        }

        HostString apiCaller = context.HttpContext.Request.Host;
        MethodInfo calledContractMethod = GetMethodInfoFromContext(context);

        var outcome = AccessTokenValidator.TryValidateTokenAndEvaluateScopes(
          rawToken, calledContractMethod, apiCaller.Host, _RequiredApiPermissions
        );

        if (outcome == AccessTokenValidator.ValidationOutcome.AccessGranted) {

          //continue with the api call...
          await next();

        }
        else if (outcome == AccessTokenValidator.ValidationOutcome.AccessDeniedTokenRequired) {
          context.Result = new ContentResult() {
            StatusCode = 401, Content = "ACCESS DENIED: an auth token (within the 'Authorization'-Header) is required for this operation!"
          };
        }
        else if (outcome == AccessTokenValidator.ValidationOutcome.AccessDeniedTokenFromBadOrigin) {
          context.Result = new ContentResult() {
            StatusCode = 401, Content = "ACCESS DENIED: the origin of the provided auth token is not trusted!"
          };
        }
        else if (outcome == AccessTokenValidator.ValidationOutcome.AccessDeniedMissingPrivileges) {
          context.Result = new ContentResult() {
            StatusCode = 401, Content = "ACCESS DENIED: you don't have the privileges for this operation!"
          };
        }
        else { //(outcome == AccessTokenValidator.ValidationOutcome.AccessDeniedTokenInvalid)
          context.Result = new ContentResult() {
            StatusCode = 401, Content = "ACCESS DENIED: the provided auth token invalid (expired/revoked/...)!"
          };
        }

      }
      catch (Exception ex) {
        context.Result = new ContentResult() {
          StatusCode = 500,
          Content = "Error during token validation: " + ex.Message
        };
      }

    }//OnActionExecutionAsync()

    /// <summary>
    /// Convenience to be used for example when initializing 'DynamicUjmwControllerOptions',
    /// which is requiring ctor-params for dynamically generated attributes...
    /// </summary>
    public static object[] BuildConstructorParams(params string[] requiredApiPermissions) {
      return new object[] { requiredApiPermissions };
    }

    private static Dictionary<string, MethodInfo> _MethodBuffer = new Dictionary<string, MethodInfo>();

    private static MethodInfo GetMethodInfoFromContext(ActionExecutingContext context) {
      string actionName = null;
      string controllerName = null;
      if (context.RouteData.Values.TryGetValue("action", out object actionUntyped)) {
        actionName = (string)actionUntyped;
      }
      if (context.RouteData.Values.TryGetValue("controller", out object controllerUntyped)) {
        controllerName = (string)controllerUntyped;
      }
      if (actionName == null) {
        return null;
      }
      string key = controllerName + "." + actionName;
      lock (_MethodBuffer) {
        if (_MethodBuffer.TryGetValue(key, out MethodInfo mth)) {
          return mth;
        }
        Type coType = context.Controller.GetType();

        //special convention, to allow referring to an explicit contractType
        PropertyInfo contractProp = coType.GetProperty("ContractType");
        if (contractProp != null) {
          coType = (Type)contractProp.GetValue(context.Controller);
        }

        //TODO: muss rekursiv werden, da sonst methoden von vererbten contracts null sind!!!
        mth = coType.GetMethod(actionName);
        _MethodBuffer.Add(key, mth);
        return mth;
      }

    }

  }//EvaluateBearerTokenAttribute

}//NS

#endif