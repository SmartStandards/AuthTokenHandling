using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;
using Microsoft.AspNetCore.Mvc.ModelBinding.Metadata;
using System.Diagnostics;

namespace Security.AccessTokenHandling.OAuthServer {

  [ApiController]
  [ApiExplorerSettings(GroupName = "OAuth")]
  [Route("oauth2")]
  public partial class OAuthServiceController : ControllerBase {

    private readonly ILogger<OAuthServiceController> _Logger;
    private readonly IOAuthService _AuthService;
    private readonly IAuthPageBuilder _AuthPageBuilder;

    public OAuthServiceController(
      ILogger<OAuthServiceController> logger, IOAuthService authService, IAuthPageBuilder authPageBuilder
    ) {
      _Logger = logger;
      _AuthService = authService;
      _AuthPageBuilder = authPageBuilder;
    }

    [Route("authorize")] //Step 1 - GET
    [HttpGet(), Produces("text/html")]
    public ActionResult GetLogonPage(
      [FromQuery(Name = "client_id")] string clientId,
      [FromQuery(Name = "redirect_uri")] string redirectUri,
      [FromQuery(Name = "state")] string state,
      [FromQuery(Name = "scope")] string rawScopePreference,
      [FromQuery(Name = "login_hint")] string loginHint,
      [FromQuery(Name = "err")] string errorMessage,
      [FromQuery(Name = "otp")] string sessionOtp,
      [FromQuery(Name = "view_mode")] int viewMode
    ) {

      //validate clientId
      HostString apiCallerHost = this.HttpContext.Request.Host;
      if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out var msg)) {
        string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewMode);
        return this.Content(errorPage, "text/html");
      }

      ScopeDescriptor[] availableScopes = null;
      string authFormTemplate;
      if (String.IsNullOrWhiteSpace(sessionOtp)) {

        string winUserName = null;

        if (loginHint == "WINAUTH") {
          loginHint = string.Empty;
#if !NET5_0 && !NET46
          WindowsIdentity windowsUserIfIdentified = null;
          try {
            windowsUserIfIdentified = (WindowsIdentity) this.HttpContext.User.Identity!;
            winUserName = windowsUserIfIdentified.Name?.ToString();
            Trace.TraceInformation($"Identified pass-trough windowws user identity: " + winUserName);
          }
          catch (Exception ex) {
            Trace.TraceWarning($"Cannot identify pass-trough windowws user identity: " + ex.Message );
          }
#else
            Trace.TraceWarning($"Cannot identify pass-trough windowws user identity: NOT IMPLEMENTED IN THIS VERSION!");
#endif
        }

        if (!String.IsNullOrWhiteSpace(winUserName)) {
          authFormTemplate = _AuthPageBuilder.GetWinAuthForm(
            "Please confirm pass-trough credentials:",
            winUserName, state, clientId, redirectUri, rawScopePreference, viewMode, ""
          );
        }
        else {
          authFormTemplate = _AuthPageBuilder.GetAuthForm(
            "Please enter your credentials:",
            loginHint, state, clientId, redirectUri, rawScopePreference, viewMode, ""
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

        if (!_AuthService.TryGetAvailableScopesBySessionOtp(clientId, sessionOtp, prefferredScopes, out availableScopes, out var msg2)) {
          string errorPage = _AuthPageBuilder.GetErrorPage(msg2, viewMode);
          return this.Content(errorPage, "text/html");
        }
        else {
          if (!string.IsNullOrWhiteSpace(errorMessage)) {
            errorMessage = $"<p><span style=\"color: red\">{errorMessage}</span><p>";
          }
          else {
            errorMessage = "";
          }
          authFormTemplate = _AuthPageBuilder.GetScopeConfirmationForm(
            "Please select the permissions to be granted:",
            sessionOtp, state, clientId, redirectUri, rawScopePreference, availableScopes, viewMode, errorMessage
          );
        }
      }

      return this.Content(authFormTemplate, "text/html", Encoding.UTF8);
    }

    [Route("authorize")] //Step2 - POST
    [HttpPost(), Produces("text/html")]
    [Consumes("application/x-www-form-urlencoded")]
    public ActionResult PostLogonForm([FromForm] IFormCollection value) {

      string login = null;
      string password = null;
      string sessionOtp = null;
      string clientId = null;
      string redirectUri = null;
      string state = null;
      string prefferredScope = "";
      int viewMode = 1;

      if (value.TryGetValue("requestedScopes", out var prefferredScopeValue)) {
        prefferredScope = prefferredScopeValue.ToString();
      }
      if (value.TryGetValue("login", out var loginValue)) {
        login = loginValue.ToString();
      }
      if (value.TryGetValue("password", out var passwordValue)) {
        password = passwordValue.ToString();
      }
      if (value.TryGetValue("otp", out var otpValue)) {
        sessionOtp = otpValue.ToString();
      }
      if (value.TryGetValue("clientId", out var clientIdValue)) {
        clientId = clientIdValue.ToString();
      }
      if (value.TryGetValue("redirectUri", out var redirectUriValue)) {
        redirectUri = redirectUriValue.ToString();
      }
      if (value.TryGetValue("state", out var stateValue)) {
        state = stateValue.ToString();
      }
      if (value.TryGetValue("viewMode", out var viewModeValue)) {
        Int32.TryParse(viewModeValue.ToString(), out viewMode);
      }

      bool winAuthSuccess = false; 
      if (string.IsNullOrEmpty(password)) {
        login = "";
#if !NET5_0 && !NET46
        WindowsIdentity windowsUserIfIdentified = null;
        try {
          windowsUserIfIdentified = (WindowsIdentity)this.HttpContext.User.Identity!;
          login = windowsUserIfIdentified.Name?.ToString();
        }
        catch (Exception ex) {
        }       
#endif
        if (string.IsNullOrEmpty(login)) { 
          string errorPage = _AuthPageBuilder.GetErrorPage("PASS-TROUGH FAILED!", viewMode);
          return this.Content(errorPage, "text/html");
        }
        else {
          winAuthSuccess = true;
        }
      }
      else {
        if (string.IsNullOrEmpty(login)) {
          string errorPage = _AuthPageBuilder.GetErrorPage("NO USERNAME PROVIDED!", viewMode);
          return this.Content(errorPage, "text/html");
        }
      }

      HostString apiCallerHost = this.HttpContext.Request.Host;
      if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out var msg)) {
        string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewMode);
        return this.Content(errorPage, "text/html");
      }

      //beim ersten post (also noch kein OTP da....)
      if (String.IsNullOrWhiteSpace(sessionOtp)) {

        //credentials prüfen...
        bool logonSuccess = _AuthService.TryAuthenticate(
          clientId, login, password, winAuthSuccess, state, out sessionOtp, out var step1Msg
        );

        //und zurück zur seite leiten
        if (logonSuccess) {
          //inkl. übergabe des OTP
          return this.Redirect($"./authorize?client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&otp={sessionOtp}");
        }
        else {
          //inkl. übergabe der fehlermeldung
          return this.Redirect($"./authorize?client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&err={step1Msg}");
        }

      }

      //beim zweiten post (mit otp), gehts jetzt nurnoch um die scope-auswahl...

      string[] selectedScopes = value.Keys.Where((k) => k.StartsWith("scope_")).Select((k) => k.Substring(6)).ToArray();

      string code = _AuthService.ValidateSessionOtpAndCreateRetrievalCode(
        clientId, login, sessionOtp, selectedScopes, out var step2Msg
      );

      if (string.IsNullOrWhiteSpace(code)) {
        return this.Redirect($"./authorize?client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&otp={sessionOtp}&view_mode={viewMode}&err={step2Msg}");
      }

      redirectUri = redirectUri + "?code=" + code;

      if (!string.IsNullOrWhiteSpace(state)) {
        redirectUri = redirectUri + "&state=" + state;
      }

      return this.Redirect(redirectUri);
    }

    [HttpPost(), Produces("application/json")]
    [Route("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public OAuthTokenResult RetrieveTokenByCode([FromForm] IFormCollection value) {

      string clientId = null;
      string clientSecret = null;
      string code = null;

      if (value.TryGetValue("client_id", out var clientIdValue)) {
        clientId = clientIdValue.ToString();
      }
      if (value.TryGetValue("client_secret", out var clientSecretValue)) {
        clientSecret = clientSecretValue.ToString();
      }
      if (value.TryGetValue("code", out var codeValue)) {
        code = codeValue.ToString();
      }

      OAuthTokenResult result = _AuthService.RetrieveTokenByCode(clientId, clientSecret, code);

      return result;
    }

    //https://www.rfc-editor.org/rfc/rfc7662
    [HttpPost(), Produces("application/json")]
    [Route("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    public Dictionary<string, object> Introspect([FromForm] IFormCollection value) {

      string token = null;
      string tokenTypeHint = null;

      if (value.TryGetValue("token", out var tokenValue)) {
        token = tokenValue.ToString();
      }

      //OPTIONAL!!!
      if (value.TryGetValue("token_type_hint", out var tokenTypeHintValue)) {
        tokenTypeHint = tokenTypeHintValue.ToString();
      }

      _AuthService.IntrospectAccessToken(token, out bool active, out var dict);
      dict["active"] = active;
      return dict;
    }

  }

}
