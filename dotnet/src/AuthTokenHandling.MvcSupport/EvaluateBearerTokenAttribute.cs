#if !NET46

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
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
          else {
            rawToken = extractedAuthHeader.ToString();
            if (rawToken.StartsWith("bearer ")) {
              rawToken = rawToken.Substring(7);
            }
          }
        }

        HostString apiCaller = context.HttpContext.Request.Host;
        //string calledMethod = context.RouteData.ToString();
        string calledMethod = context.ActionDescriptor.DisplayName;

        var outcome = AccessTokenValidator.TryValidateTokenAndEvaluateScopes(
          rawToken, apiCaller.Host, calledMethod, _RequiredApiPermissions
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

  }//EvaluateBearerTokenAttribute

}//NS

#endif