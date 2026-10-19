#if !NET46

using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;
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
        if (context.HttpContext.Request.Headers.TryGetValue("Authorization", out StringValues extractedAuthHeader)) {

          rawToken = StripTokenPrefix(extractedAuthHeader.ToString());

          if (String.IsNullOrWhiteSpace(rawToken)) {
            rawToken = null;
          }
   
        }

        int httpReturnCode = 200;
        string httpReasonPhrase = string.Empty;
        string apiCaller = context.HttpContext.Connection.RemoteIpAddress.ToString();
        MethodInfo calledContractMethod = GetMethodInfoFromContext(context, out Type contractType);
        ExtendedAuthRequiredResponse extendedAuthRequiredResponse;

        if (AccessTokenValidator.TryValidateHttpAuthHeader(
          rawToken, contractType, calledContractMethod, apiCaller,
          ref httpReturnCode, ref httpReasonPhrase,
          out extendedAuthRequiredResponse,
          _RequiredApiPermissions
        )) {

          //continue with the api call...
          await next();

        }
        else {
          ApplyExtendedAuthRequiredResponse(
            context.HttpContext,
            ref httpReturnCode,
            ref httpReasonPhrase,
            extendedAuthRequiredResponse
          );
          ApplyProtectedResourceMetadataChallenge(context.HttpContext, httpReturnCode);
          context.Result = new ContentResult() {
            StatusCode = httpReturnCode,
            Content = httpReasonPhrase
          };
        }

      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        context.Result = new ContentResult() {
          StatusCode = 500,
          Content = "Internal Server Error (EBT-ATR)"
        };
      }

    }//OnActionExecutionAsync()

    /// <summary>
    /// Emits the RFC 9728 'WWW-Authenticate: Bearer resource_metadata="..."' challenge for 401 responses,
    /// if the protected-resource discovery endpoint was registered and no challenge was set by a custom hook.
    /// The metadata URL is qualified on-demand using the incoming request.
    /// </summary>
    private static void ApplyProtectedResourceMetadataChallenge(HttpContext httpContext, int httpReturnCode) {
      if (httpReturnCode != 401) {
        return;
      }
      if (httpContext.Response.Headers.ContainsKey("WWW-Authenticate")) {
        return;
      }
      string challenge;
      if (WellKnownOAuthProtectedResourceRegistry.TryBuildBearerChallenge(httpContext.Request, out challenge)) {
        httpContext.Response.Headers["WWW-Authenticate"] = challenge;
      }
    }

    private static void ApplyExtendedAuthRequiredResponse(
      HttpContext httpContext,
      ref int httpReturnCode,
      ref string httpReasonPhrase,
      ExtendedAuthRequiredResponse extendedAuthRequiredResponse
    ) {
      if (extendedAuthRequiredResponse == null) {
        return;
      }

      if (extendedAuthRequiredResponse.StatusCode >= 100) {
        httpReturnCode = extendedAuthRequiredResponse.StatusCode;
      }
      if (!string.IsNullOrWhiteSpace(extendedAuthRequiredResponse.ReasonPhrase)) {
        httpReasonPhrase = extendedAuthRequiredResponse.ReasonPhrase;
      }

      if (extendedAuthRequiredResponse.Headers == null) {
        return;
      }

      foreach (HttpResponseHeader header in extendedAuthRequiredResponse.Headers) {
        if (header == null) {
          continue;
        }
        if (string.IsNullOrWhiteSpace(header.Name)) {
          continue;
        }
        httpContext.Response.Headers[header.Name] = header.Value;
      }
    }

    /// <summary>
    /// Convenience to be used for example when initializing 'DynamicUjmwControllerOptions',
    /// which is requiring ctor-params for dynamically generated attributes...
    /// </summary>
    public static object[] BuildConstructorParams(params string[] requiredApiPermissions) {
      return new object[] { requiredApiPermissions };
    }

    private static Dictionary<string, MethodInfo> _MethodBuffer = new Dictionary<string, MethodInfo>();
    private static Dictionary<string, Type> _ContractBuffer = new Dictionary<string, Type>();
    private static MethodInfo GetMethodInfoFromContext(ActionExecutingContext context, out Type contractType) {
      string actionName = null;
      string controllerName = null;
      if (context.RouteData.Values.TryGetValue("action", out object actionUntyped)) {
        actionName = (string)actionUntyped;
      }
      if (context.RouteData.Values.TryGetValue("controller", out object controllerUntyped)) {
        controllerName = (string)controllerUntyped;
      }
      if (actionName == null) {
        contractType = null;
        return null;
      }
      string key = controllerName + "." + actionName;
      lock (_MethodBuffer) {
        lock (_ContractBuffer) {
          if (_MethodBuffer.TryGetValue(key, out MethodInfo mth)) {
            _ContractBuffer.TryGetValue(key, out contractType);
            return mth;
          }
          contractType = context.Controller.GetType();

          //special convention, to allow referring to an explicit contractType
          PropertyInfo contractProp = contractType.GetProperty("ContractType");
          if (contractProp != null) {
            contractType = (Type)contractProp.GetValue(context.Controller);
          }

          //TODO: muss rekursiv werden, da sonst methoden von vererbten contracts null sind!!!
          mth = contractType.GetMethod(actionName);

          _MethodBuffer.Add(key, mth);
          _ContractBuffer.Add(key, contractType);
          return mth;
        }
      }

    }

    private readonly static string[] _KnownTokenPrefixes = new string[] { "Bearer", "JWT" };
    internal static string StripTokenPrefix(string rawToken) {
      foreach (string prefix in _KnownTokenPrefixes) {
        if (rawToken != null && rawToken.StartsWith(prefix + " ", StringComparison.CurrentCultureIgnoreCase)) {
          return rawToken.Substring(prefix.Length + 1);
        }
      }
      return rawToken;
    }

  }//EvaluateBearerTokenAttribute

}//NS

#endif