using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Security;

namespace Security.AccessTokenHandling.OAuthServer {

    [ApiController]
    [ApiExplorerSettings(GroupName = "OAuth")]
    [Route("oauth")]
    public partial class OAuthController : ControllerBase {

      private readonly ILogger<OAuthController> _Logger;
      private readonly IOAuthService _OAuthService;
      private readonly string _CibaTemplate1;
      private readonly string _CibaTemplate2;
      private readonly string _CibaTemplate1emd;
      private readonly string _CibaTemplate2emd;
      private readonly string _ErrorTemplate;
      private readonly string _ErrorTemplateemd;
      private readonly string _TokenTemplate;
      private readonly string _ScopeTemplate = "          <label><input type=\"checkbox\" name=\"scope_{{expr}}\" id=\"scope_{{expr}}\"{{checked}}{{readonly}} > {{label}} </label><br />";

      public OAuthController(ILogger<OAuthController> logger, IOAuthService oAuthService) {
        _Logger = logger;
        _OAuthService = oAuthService;

        var assembly = this.GetType().Assembly;

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.Ciba1.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _CibaTemplate1 = reader.ReadToEnd();
        }

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.Ciba2.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _CibaTemplate2 = reader.ReadToEnd();
        }

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.Ciba1emd.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _CibaTemplate1emd = reader.ReadToEnd();
        }

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.Ciba2emd.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _CibaTemplate2emd = reader.ReadToEnd();
        }

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.Error.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _ErrorTemplate = reader.ReadToEnd();
        }

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.Erroremd.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _ErrorTemplateemd = reader.ReadToEnd();
        }

        using (Stream stream = assembly.GetManifestResourceStream("EmbeddedTemplates.TokenDisplay.html"))
        using (StreamReader reader = new StreamReader(stream)) {
          _TokenTemplate = reader.ReadToEnd();
        }

      }

      [Route("authorize")] //Step 1 - GET
      [HttpGet(), Produces("text/html")]
      public ActionResult GetLogonPage(
        [FromQuery(Name = "client_id")] string clientId,
        [FromQuery(Name = "redirect_uri")] string redirectUri,
        [FromQuery(Name = "state")] string state,
        [FromQuery(Name = "scope")]string rawScopePreference,
        [FromQuery(Name = "login_hint")] string loginHint,
        [FromQuery(Name = "err")] string errorMessage,
        [FromQuery(Name = "otp")] string otp,
        [FromQuery(Name = "view_mode")] int viewMode
      ) {

        //var customizing = _OAuthService.GetEnvironmentUiCustomizing(clientId);

        //validate clientId
        HostString apiCallerHost = this.HttpContext.Request.Host;
        if (!_OAuthService.ValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out var msg)) {
          StringBuilder errorHtmlBuilder;
          if (viewMode == 2) {
            errorHtmlBuilder = new StringBuilder(_ErrorTemplateemd);
          }
          else {
            errorHtmlBuilder = new StringBuilder(_ErrorTemplate);
          }
          errorHtmlBuilder.Replace("{{title}}", customizing.AuthPageTitle);
          errorHtmlBuilder.Replace("{{bgcolor}}", customizing.AuthPageBgColor);
          errorHtmlBuilder.Replace("{{message}}", msg);
          errorHtmlBuilder.Replace("{{legal_url}}", customizing.LegalUrl);
          errorHtmlBuilder.Replace("{{portal_url}}", customizing.PortalUrl);
          return this.Content(errorHtmlBuilder.ToString(), "text/html");
        }

        ScopeDescriptor[] availableScopes = null;
        StringBuilder htmlBuilder;
        if (String.IsNullOrWhiteSpace(otp)) {
          if (viewMode == 2) {
            htmlBuilder = new StringBuilder(_CibaTemplate1emd);
          }
          else {
            htmlBuilder = new StringBuilder(_CibaTemplate1);
          }
          htmlBuilder.Replace("{{scope_checks}}", "");
          htmlBuilder.Replace("{{prompt}}", customizing.AuthPageLogonText);
        }
        else {
          if (viewMode == 2) {
            htmlBuilder = new StringBuilder(_CibaTemplate2emd);
          }
          else {
            htmlBuilder = new StringBuilder(_CibaTemplate2);
          }
          htmlBuilder.Replace("{{otp}}", otp);
          htmlBuilder.Replace("{{prompt}}", "Bitte wählen sie die zu erteilenden Berechtigungen");
          string[] prefferredScopes;
          if (rawScopePreference != null) {
            prefferredScopes = rawScopePreference.Split(' ').Where((s) => !String.IsNullOrWhiteSpace(s)).ToArray();
          }
          else {
            prefferredScopes = new string[] { };
          }

          if (!_OAuthService.GetAvailableScopesByOtp(clientId, otp, prefferredScopes, out availableScopes, out var msg2)) {
            StringBuilder errorHtmlBuilder;
            if (viewMode == 2) {
              errorHtmlBuilder = new StringBuilder(_ErrorTemplateemd);
            }
            else {
              errorHtmlBuilder = new StringBuilder(_ErrorTemplate);
            }
            errorHtmlBuilder.Replace("{{title}}", customizing.AuthPageTitle);
            errorHtmlBuilder.Replace("{{bgcolor}}", customizing.AuthPageBgColor);
            errorHtmlBuilder.Replace("{{message}}", msg2);
            errorHtmlBuilder.Replace("{{legal_url}}", customizing.LegalUrl);
            errorHtmlBuilder.Replace("{{portal_url}}", customizing.PortalUrl);

            return this.Content(errorHtmlBuilder.ToString(), "text/html");

          }
          else {
            var scopeChecks = new StringBuilder();
            foreach (var availableScope in availableScopes.Where((s) => !s.Invisible)) {
              var line = _ScopeTemplate;
              if (availableScope.Selected) {
                line = line.Replace("{{checked}}", " checked=\"checked\"");
              }
              else {
                line = line.Replace("{{checked}}", "");
              }
              if (availableScope.ReadOnly) {
                line = line.Replace("{{readonly}}", " disabled=\"disabled\"");
              }
              else {
                line = line.Replace("{{readonly}}", "");
              }
              line = line.Replace("{{label}}", availableScope.Label);
              line = line.Replace("{{expr}}", availableScope.Expression);
              scopeChecks.AppendLine(line);
            }
            htmlBuilder.Replace("{{scope_checks}}", scopeChecks.ToString());
          }

        }

        //string[] invalidScopes = _OAuthService.GetInvalidScopes(prefferredScopes, clientId);
        //if (invalidScopes.Any()) {
        //  var errorHtmlBuilder = new StringBuilder(_ErrorTemplate);
        //  errorHtmlBuilder.Replace("{{title}}", _OAuthService.GetLogonTitle(clientId));
        //  errorHtmlBuilder.Replace("{{message}}", String.Join("<br>", invalidScopes.Select((s)=> "'" + s + "' is not a Valid Scope!")));
        //  errorHtmlBuilder.Replace("{{legal_url}}", _OAuthService.GetLegalUrl(clientId));
        //  errorHtmlBuilder.Replace("{{portal_url}}", _OAuthService.GetPortalUrl(clientId));
        //  return this.Content(errorHtmlBuilder.ToString(), "text/html");
        //}

        //profile based
        htmlBuilder.Replace("{{title}}", customizing.AuthPageTitle);
        htmlBuilder.Replace("{{bgcolor}}", customizing.AuthPageBgColor);
        htmlBuilder.Replace("{{legal_url}}", customizing.LegalUrl);
        htmlBuilder.Replace("{{portal_url}}", customizing.PortalUrl);
        htmlBuilder.Replace("{{logo}}", $"<div align=\"center\"><img src=\"{customizing.AuthPageLogoImage}\" width=\"150\" /></div>");

        //url based
        htmlBuilder.Replace("{{clientId}}", clientId);
        htmlBuilder.Replace("{{redirectUri}}", redirectUri);
        htmlBuilder.Replace("{{state}}", state);
        htmlBuilder.Replace("{{requestedScopes}}", rawScopePreference);
        htmlBuilder.Replace("{{login_hint}}", loginHint);
        htmlBuilder.Replace("{{viewMode}}", viewMode.ToString());

        if (string.IsNullOrWhiteSpace(errorMessage)) {
          htmlBuilder.Replace("{{error}}", "");
        }
        else {
          htmlBuilder.Replace("{{error}}", $"<p><span style=\"color: red\">{errorMessage}</span><p>");
        }

        return this.Content(htmlBuilder.ToString(), "text/html", Encoding.UTF8);
      }

      [Route("authorize")] //Step2 - POST
      [HttpPost(), Produces("text/html")]
      [Consumes("application/x-www-form-urlencoded")] //[SwaggerOperation(OperationId = nameof(PostLogonForm), Description = "Receives the Submit-Post from the Logon Page (html form)")]
      public ActionResult PostLogonForm([FromForm] IFormCollection value) { //[SwaggerRequestBody(Required = true)]

        string login = null;
        string password = null;
        string otp = null;
        string clientId = null;
        string redirectUri = null;
        string state = null;
        string prefferredScope = "";

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
          otp = otpValue.ToString();
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
        if (value.TryGetValue("viewMode", out var viewMode)) {
          state = stateValue.ToString();
        }

        HostString apiCallerHost = this.HttpContext.Request.Host;
        if (!_OAuthService.ValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out var msg)) {
          var customizing = _OAuthService.GetEnvironmentUiCustomizing(clientId);
          StringBuilder errorHtmlBuilder;
          if (viewMode == 2) {
            errorHtmlBuilder = new StringBuilder(_ErrorTemplateemd);
          }
          else {
            errorHtmlBuilder = new StringBuilder(_ErrorTemplate);
          }
          errorHtmlBuilder.Replace("{{title}}", customizing.AuthPageTitle);
          errorHtmlBuilder.Replace("{{message}}", msg);
          errorHtmlBuilder.Replace("{{legal_url}}", customizing.LegalUrl);
          errorHtmlBuilder.Replace("{{portal_url}}", customizing.PortalUrl);
          return this.Content(errorHtmlBuilder.ToString(), "text/html");
        }

        //beim ersten post (also noch kein OTP da....)
        if (String.IsNullOrWhiteSpace(otp)) {

          //credentials prüfen...
          bool logonSuccess = _OAuthService.ValidateCredentialsAndGetOtp(
            clientId, login, password, out otp, out var step1Msg
          );

          //und zurück zur seite leiten
          if (logonSuccess) {
            //inkl. übergabe des OTP
            return this.Redirect($"./oauth?client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&otp={otp}");
          }
          else {
            //inkl. übergabe der fehlermeldung
            return this.Redirect($"./oauth?client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&err={step1Msg}");
          }

        }

        //beim zweiten post (mit otp), gehts jetzt nurnoch um die scope-auswahl...

        string[] selectedScopes = value.Keys.Where((k) => k.StartsWith("scope_")).Select((k) => k.Substring(6)).ToArray();

        string code = _OAuthService.ValidateOtpAndCreateTokenCode(
          clientId, login, otp, selectedScopes, out var step2Msg
        );

        if (string.IsNullOrWhiteSpace(code)) {
          return this.Redirect($"./oauth?client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&otp={otp}&view_mode={viewMode}&err={step2Msg}");
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

        OAuthTokenResult result = _OAuthService.RetrieveTokenByCode(clientId, clientSecret, code);

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

       _OAuthService.IntrospectAccessToken(token,out bool active,out var dict);
        dict["active"] = active;
        return dict;
      }

    }

}
