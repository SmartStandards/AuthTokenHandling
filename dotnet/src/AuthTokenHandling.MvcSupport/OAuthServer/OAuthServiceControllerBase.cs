using Logging.SmartStandards;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;

namespace Security.AccessTokenHandling.OAuthServer {

  [ApiController]
  [ApiExplorerSettings(GroupName = "OAuth")]
  [Route("oauth2")]
  internal partial class OAuth2Controller : ControllerBase {

    private readonly ILogger<OAuth2Controller> _Logger;
    private readonly IOAuthService _AuthService;
    private readonly IAuthPageBuilder _AuthPageBuilder;

    public OAuth2Controller(
      ILogger<OAuth2Controller> logger, IOAuthService authService, IAuthPageBuilder authPageBuilder
    ) {
      _Logger = logger;
      _AuthService = authService;
      _AuthPageBuilder = authPageBuilder;
    }

    /// <summary>
    ///   Landing-Page nach Browser-Redirect (HTTP-GET)
    /// </summary>
    /// <param name="responseType">'code' oder 'token'</param>
    /// <param name="clientId"></param>
    /// <param name="redirectUri"></param>
    /// <param name="state"></param>
    /// <param name="rawScopePreference"></param>
    /// <param name="loginHint"></param>
    /// <param name="errorMessageViaRoundtrip"></param>
    /// <param name="sessionId"></param>
    /// <param name="viewMode"></param>
    /// <returns></returns>
    [Route("authorize")] //Step 1 - GET
    [HttpGet(), Produces("text/html")]
    public ActionResult GetLogonPage(
      [FromQuery(Name = "response_type")] string responseType,
      [FromQuery(Name = "client_id")] string clientId,
      [FromQuery(Name = "redirect_uri")] string redirectUri,
      [FromQuery(Name = "state")] string state,
      [FromQuery(Name = "scope")] string rawScopePreference,
      [FromQuery(Name = "login_hint")] string loginHint,
      [FromQuery(Name = "err")] string errorMessageViaRoundtrip,
      [FromQuery(Name = "otp")] string sessionId,
      [FromQuery(Name = "view_mode")] int viewMode
    ) {

      AuthPageViewModeOptions viewOpt = new AuthPageViewModeOptions();
      viewOpt.LowSpaceEmbedded = (viewMode == 2);

      try {

        if (string.IsNullOrWhiteSpace(responseType)) {
          string errorPage = _AuthPageBuilder.GetErrorPage("Url-param 'response_type' is missing! Please provide one ('code'/'token'/'display'/...)", viewOpt);
          return this.Content(errorPage, "text/html");
        }

        //validate clientId
        HostString apiCallerHost = this.HttpContext.Request.Host;
        if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out var msg)) {
          string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewOpt);
          return this.Content(errorPage, "text/html");
        }

        ScopeDescriptor[] availableScopes = null;
        string authFormTemplate;
        if (String.IsNullOrWhiteSpace(sessionId)) {

          string winUserName = null;

          if (loginHint == "pass-trough" || loginHint == "WINAUTH") {
            loginHint = string.Empty;

            if (this.TryGetPasstroughUserIdentity(out winUserName)) {

              //no UI / unattended
              if (viewMode == 3 && !String.IsNullOrWhiteSpace(winUserName)) {
                string[] selectedScopes = rawScopePreference.Split(' ');
                bool logonSuccess = _AuthService.TryAuthenticate(
                  clientId, winUserName, null, true, state, out sessionId, out string step1Msg
                );
                bool success = _AuthService.TryValidateSessionIdAndCreateRetrievalCode(
                  clientId, sessionId, selectedScopes, out string code, out string step2Msg
                );
                if (redirectUri.Contains("?")) {
                  redirectUri = redirectUri + "&";
                }
                else {
                  redirectUri = redirectUri + "?";
                }
                redirectUri = redirectUri + "code=" + code;

                if (!string.IsNullOrWhiteSpace(state)) {
                  redirectUri = redirectUri + "&state=" + state;
                }

                return this.Redirect(redirectUri);
              }

            }

          }

          if (!string.IsNullOrWhiteSpace(errorMessageViaRoundtrip)) {
            //HACK: hier darf natürlich kein html sein!
            errorMessageViaRoundtrip = $"<p><span style=\"color: red\">{errorMessageViaRoundtrip}</span><p>";
          }
          else {
            errorMessageViaRoundtrip = "";
          }

          if (!String.IsNullOrWhiteSpace(winUserName)) {
            authFormTemplate = _AuthPageBuilder.GetWinAuthForm(
              responseType, "Please confirm pass-trough credentials:",
              winUserName, state, clientId, redirectUri, rawScopePreference, viewOpt, errorMessageViaRoundtrip
            );
          }
          else {
            authFormTemplate = _AuthPageBuilder.GetAuthForm(
              responseType, "Please enter your credentials:",
              loginHint, state, clientId, redirectUri, rawScopePreference, viewOpt, errorMessageViaRoundtrip
            );
          }

        }
        else {

          string[] prefferredScopes;
          if (rawScopePreference != null) {
            prefferredScopes = rawScopePreference.Split(' ').Where((s) => !String.IsNullOrWhiteSpace(s)).ToArray();
          }
          else {
            prefferredScopes = new string[] { };
          }

          if (!_AuthService.TryGetAvailableScopesBySessionId(clientId, sessionId, prefferredScopes, out availableScopes, out var msg2)) {
            string errorPage = _AuthPageBuilder.GetErrorPage(msg2, viewOpt);
            return this.Content(errorPage, "text/html");
          }
          else {
            if (!string.IsNullOrWhiteSpace(errorMessageViaRoundtrip)) {
              //HACK: natürlich darf hier kein html sein
              errorMessageViaRoundtrip = $"<p><span style=\"color: red\">{errorMessageViaRoundtrip}</span><p>";
            }
            else {
              errorMessageViaRoundtrip = "";
            }
            authFormTemplate = _AuthPageBuilder.GetScopeConfirmationForm(
              responseType, "Please select the access scopes to be granted:",
              sessionId, state, clientId, redirectUri, rawScopePreference, availableScopes, viewOpt, errorMessageViaRoundtrip
            );
          }
        }

        return this.Content(authFormTemplate, "text/html", Encoding.UTF8);
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        string errorPage = _AuthPageBuilder.GetErrorPage("Processing Error: " + ex.Message, viewOpt);
        return this.Content(errorPage, "text/html");
      }
    }

    [Route("authorize")] //Step2 - POST
    [HttpPost(), Produces("text/html")]
    [Consumes("application/x-www-form-urlencoded")]
    public ActionResult PostLogonForm([FromForm] IFormCollection value) {

      string login = null;
      string password = null;
      string sessionId = null;
      string clientId = null;
      string redirectUri = null;
      string state = null;
      string prefferredScope = "";
      int viewMode = 1;
      AuthPageViewModeOptions viewOpt = new AuthPageViewModeOptions();


      try {

        string responseType = null;
        if (value.TryGetValue("responseType", out StringValues responseTypeValue)) {
          responseType = responseTypeValue.ToString();
        }

        if (value.TryGetValue("requestedScopes", out StringValues prefferredScopeValue)) {
          prefferredScope = prefferredScopeValue.ToString();
        }
        if (value.TryGetValue("login", out StringValues loginValue)) {
          login = loginValue.ToString();
        }
        if (value.TryGetValue("password", out StringValues passwordValue)) {
          password = passwordValue.ToString();
        }
        if (value.TryGetValue("otp", out StringValues sessionIdValue)) {
          sessionId = sessionIdValue.ToString();
        }
        if (value.TryGetValue("clientId", out StringValues clientIdValue)) {
          clientId = clientIdValue.ToString();
        }
        if (value.TryGetValue("redirectUri", out StringValues redirectUriValue)) {
          redirectUri = redirectUriValue.ToString();
        }
        if (value.TryGetValue("state", out StringValues stateValue)) {
          state = stateValue.ToString();
        }
        if (value.TryGetValue("viewMode", out StringValues viewModeValue)) {
          Int32.TryParse(viewModeValue.ToString(), out viewMode);
          viewOpt.LowSpaceEmbedded = (viewMode == 2);
        }

        HostString apiCallerHost = this.HttpContext.Request.Host;
        if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out string msg)) {
          string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewOpt);
          return this.Content(errorPage, "text/html");
        }

        //beim ersten post (also noch kein OTP da....)
        if (String.IsNullOrWhiteSpace(sessionId)) {

          bool winAuthSuccess = false;
          if (string.IsNullOrEmpty(password)) {
            login = "";
            if (!this.TryGetPasstroughUserIdentity(out login) || string.IsNullOrEmpty(login)) {
              string errorPage = _AuthPageBuilder.GetErrorPage("PASS-THROUGH FAILED!", viewOpt);
              return this.Content(errorPage, "text/html");
            }
            else {
              winAuthSuccess = true;
            }
          }
          else {
            if (string.IsNullOrEmpty(login)) {
              string errorPage = _AuthPageBuilder.GetErrorPage("NO USERNAME PROVIDED!", viewOpt);
              return this.Content(errorPage, "text/html");
            }
          }

          //credentials prüfen...
          bool logonSuccess = _AuthService.TryAuthenticate(
            clientId, login, password, winAuthSuccess, state, out sessionId, out var step1Msg
          );

          //und zurück zur seite leiten
          if (logonSuccess) {
            //inkl. übergabe des OTP
            return this.Redirect($"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&otp={sessionId}");
          }
          else {
            //inkl. übergabe der fehlermeldung
            return this.Redirect($"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&err={step1Msg}");
          }

        }

        //beim zweiten post (mit otp), gehts jetzt nurnoch um die scope-auswahl...

        string[] selectedScopes = value.Keys.Where((k) => k.StartsWith("scope_")).Select((k) => k.Substring(6)).ToArray();

        if (redirectUri.Contains("?")) {
          redirectUri = redirectUri + "&";
        }
        else {
          redirectUri = redirectUri + "?";
        }

        if (responseType.Equals("code", StringComparison.InvariantCultureIgnoreCase)) {

          bool success = _AuthService.TryValidateSessionIdAndCreateRetrievalCode(
            clientId, sessionId, selectedScopes, out string code, out string step2Msg
          );

          if (!success || string.IsNullOrWhiteSpace(code)) {
            return this.Redirect($"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&otp={sessionId}&view_mode={viewMode}&err={step2Msg}");
          }

          redirectUri = redirectUri + "code=" + code;
        }
        else if (responseType.Equals("token", StringComparison.InvariantCultureIgnoreCase)) {
          //token oder id_token kann gefordert sein!

          TokenIssuingResult tokenResult = null;
          if (_AuthService.TryValidateSessionIdAndCreateToken(clientId, sessionId, selectedScopes, out tokenResult)) {
            redirectUri = redirectUri + tokenResult.ToString();
          }
          else {
            if(!string.IsNullOrWhiteSpace(tokenResult?.error)) {
              redirectUri = redirectUri + "error=" + tokenResult.error;
            }
            else {
              redirectUri = redirectUri + "error=no-token";
            }       
          }
        }
        else if (responseType.Equals("display", StringComparison.InvariantCultureIgnoreCase)) {
          if (_AuthService.TryValidateSessionIdAndCreateToken(clientId, sessionId, selectedScopes, out TokenIssuingResult result)) {
            string displayPage = _AuthPageBuilder.GetTokenDisplayPage(result, viewOpt);
            return this.Content(displayPage, "text/html");
          }
          else {
            string errorPage = _AuthPageBuilder.GetErrorPage("Got no Token to display...", viewOpt);
            return this.Content(errorPage, "text/html");
          }
        }
        else {
          redirectUri = redirectUri + "error=unknown-response-type";
        }

        if (!string.IsNullOrWhiteSpace(state)) {
          redirectUri = redirectUri + "&state=" + state;
        }
        return this.Redirect(redirectUri);
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        string errorPage = _AuthPageBuilder.GetErrorPage("Processing Error: " + ex.Message, viewOpt);
        return this.Content(errorPage, "text/html");
      }
    }

    [HttpPost(), Produces("application/json")]
    [Route("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public TokenIssuingResult RetrieveToken([FromForm] IFormCollection value) {
      try {
        string grantType = null;
        string clientId = null;
        string clientSecret = null;


        if (value.TryGetValue("grant_type", out StringValues grantTypeValue)) {
          grantType = grantTypeValue.ToString();
        }
        if (value.TryGetValue("client_id", out StringValues clientIdValue)) {
          clientId = clientIdValue.ToString();
        }
        if (value.TryGetValue("client_secret", out StringValues clientSecretValue)) {
          clientSecret = clientSecretValue.ToString();
        }

        if (grantType == "authorization_code") {

          string code = null;
          if (value.TryGetValue("code", out StringValues codeValue)) {
            code = codeValue.ToString();
          }

          TokenIssuingResult result = _AuthService.RetrieveTokenByCode(clientId, clientSecret, code);
          return result;
        } 
        else if (grantType == "client_credentials") {

          string[] requestedScopes = Array.Empty<string>();
          if (value.TryGetValue("scope", out StringValues scopeValue)) {
            requestedScopes = scopeValue.ToString().Split(' ');
          }

          TokenIssuingResult result = _AuthService.ValidateClientAndCreateToken(
            clientId, clientSecret, requestedScopes
          );
          return result;
        }
        else if (grantType == "refresh_token") {

          string refreshToken = null;
          if (value.TryGetValue("refresh_token", out StringValues refTokenValue)) {
            refreshToken = refTokenValue.ToString();
          }

          TokenIssuingResult result = _AuthService.CreateFollowUpToken(
            refreshToken
          );
          return result;
        }
        else {
          return new TokenIssuingResult {
            error = $"Grant-Type '{grantType}' not supported!",
            error_description = $"Grant-Type '{grantType}' not supported!"
          };
        }
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        return new TokenIssuingResult {
          error = "Processing Error",
          error_description = ex.Message
        };
      }
    }

    /// <summary>
    /// This is just a proxy-method which allows the usage of a http-get instead of post.
    /// It is NOT part of the oauth2 standard, but resolved the problem, that browsers
    /// will make CORS problems when a SPA is tying to retrieve a token via post using javascript.
    /// </summary>
    /// <param name="grantType"></param>
    /// <param name="clientId"></param>
    /// <param name="clientSecret"></param>
    /// <param name="code"></param>
    /// <returns></returns>
    [HttpGet(), Produces("application/json")]
    [Route("token")]
    public TokenIssuingResult RetrieveTokenViaGet(
      [FromQuery(Name = "grant_type")] string grantType,
      [FromQuery(Name = "client_id")] string clientId,
      [FromQuery(Name = "client_secret")] string clientSecret,
      [FromQuery(Name = "code")] string code
    ) {
      try {

        var args = new Dictionary<string, StringValues>();

        args["grant_type"] = grantType;
        args["client_id"] = clientId;
        args["client_secret"] = clientSecret;
        args["code"] = code;

        return this.RetrieveToken(new FormCollection(args));
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        return new TokenIssuingResult { 
          error = "Processing Error",
          error_description = ex.Message
        };
      }
    }

    //https://www.rfc-editor.org/rfc/rfc7662
    [HttpPost(), Produces("application/json")]
    [Route("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    public Dictionary<string, object> Introspect([FromForm] IFormCollection value) {
      try {

        string token = null;
        string tokenTypeHint = null;

        if (value.TryGetValue("token", out StringValues tokenValue)) {
          token = tokenValue.ToString();
        }

        //OPTIONAL!!!
        if (value.TryGetValue("token_type_hint", out StringValues tokenTypeHintValue)) {
          tokenTypeHint = tokenTypeHintValue.ToString();
        }

        _AuthService.IntrospectAccessToken(token, out bool active, out Dictionary<String, object> dict);
        dict["active"] = active;

        return dict;
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        return new Dictionary<string, object>() {
          { "active", false },
          { "inactive_reason", "Processing Error (Introspection Endpoint)" },
        };
      }
    }

    private bool TryGetPasstroughUserIdentity(out string userName) {
      userName = null;
#if !NET5_0 && !NET46
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
          Trace.TraceWarning($"Cannot identify pass-trough user identity: Unknown identity-class");
        }
        Trace.TraceInformation($"Identified pass-trough user identity: " + userName);
      }
      catch (Exception ex) {
        Trace.TraceWarning($"Cannot identify pass-trough user identity: " + ex.Message);
      }
#else
      Trace.TraceWarning($"Cannot identify pass-trough user identity: NOT IMPLEMENTED IN THIS VERSION!");
#endif
      return !string.IsNullOrWhiteSpace(userName);
    }

  }

}
