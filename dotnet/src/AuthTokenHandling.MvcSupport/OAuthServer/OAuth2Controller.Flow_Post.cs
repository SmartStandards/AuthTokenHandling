using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System;
using System.Linq;
using System.Web;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller : ControllerBase {

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // AUTHORIZE STEP #2 - FORM SUBMIT (HTTP-POST)                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    [Route("sso/authorize")] //Step2 - POST
    [HttpPost(), Produces("text/html")]
    [Consumes("application/x-www-form-urlencoded")]
    [Authorize(Policy = "WindowsOnly")]
    public ActionResult PostLogonFormSso([FromForm] IFormCollection value) {

      if (!this.TryGetPasstroughUserIdentity(out string winUserName)) {
        return Challenge("Negotiate");
      }

      return this.PostLogonForm(value);
    }

    [Route("authorize")] //Step2 - POST
    [HttpPost(), Produces("text/html")]
    [Consumes("application/x-www-form-urlencoded")]
    [AllowAnonymous]
    public ActionResult PostLogonForm([FromForm] IFormCollection value) {

      string login = null;
      string password = null;
      string sessionId = null;
      string clientId = null;
      string redirectUri = null;
      string state = null;
      string prefferredScope = "";
      int viewMode = 1;
      string responseType = null;
      string codeChallenge = null;
      string resource = null;

      AuthPageViewModeOptions viewOpt = new AuthPageViewModeOptions();

      try {

        #region " Read/Parse POST-Params "

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
        if (value.TryGetValue(_PkceFormFieldName, out StringValues codeChallengeValue)) {
          codeChallenge = codeChallengeValue.ToString();
        }
        if (value.TryGetValue(_ResourceFormFieldName, out StringValues resourceValue)) {
          resource = resourceValue.ToString();
        }

        #endregion

        //VALIDATE clientId first...
        HostString apiCallerHost = this.HttpContext.Request.Host;
        if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out string msg)) {
          string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewOpt);
          return this.Content(errorPage, "text/html");
        }

        //the code challenge has already been validated on GET, but the form could have been manipulated
        if (!string.IsNullOrEmpty(codeChallenge) && !IsValidS256Challenge(codeChallenge)) {
          string errorPage = _AuthPageBuilder.GetErrorPage("Invalid 'code_challenge'!", viewOpt);
          return this.Content(errorPage, "text/html");
        }

        //the resource has already been checked on GET, but the form could have been manipulated (tolerant: dropped)
        if (!TryValidateResourceParam(resource, out string resourceError)) {
          resource = null;
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////

        //beim ersten post (also noch keine sessionId da....)
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

          string redirectUrl = $"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&otp={sessionId}";

          //credentials prüfen...
          bool logonSuccess = _AuthService.TryAuthenticate(
            clientId, login, password, winAuthSuccess, state, out sessionId, out var step1Msg
          );

          //und zurück zur seite leiten
          if (logonSuccess) {
            //inkl. übergabe des OTP
            return this.Redirect(AppendRoundtripQueryParams($"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&otp={sessionId}", codeChallenge, resource));
          }
          else {
            //inkl. übergabe der fehlermeldung
            return this.Redirect(AppendRoundtripQueryParams($"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&view_mode={viewMode}&err={step1Msg}", codeChallenge, resource));
          }

        }

        //beim zweiten post (mit otp), gehts jetzt nurnoch um die scope-auswahl...

        string[] selectedScopes = value.Keys.Where((k) => k.StartsWith("scope_")).Select((k) => k.Substring(6)).ToArray();

        //if (redirectUri.Contains("?")) {
        //  redirectUri = redirectUri + "&";
        //}
        //else {
        //  redirectUri = redirectUri + "?";
        //}

        if (responseType.Equals("code", StringComparison.InvariantCultureIgnoreCase)) {

          bool success = _AuthService.TryValidateSessionIdAndCreateRetrievalCode(
            clientId, sessionId, selectedScopes, codeChallenge, resource, out string code, out string step2Msg
          );

          if (!success || string.IsNullOrWhiteSpace(code)) {
            return this.Redirect(AppendRoundtripQueryParams($"./authorize?response_type={responseType}&client_id={clientId}&state={state}&scope={prefferredScope}&login_hint={login}&redirect_uri={redirectUri}&otp={sessionId}&view_mode={viewMode}&err={step2Msg}", codeChallenge, resource));
          }

          redirectUri = AppendUrlParam(redirectUri, "code", code, false);
        }
        else if (responseType.Equals("token", StringComparison.InvariantCultureIgnoreCase)) {
          //token oder id_token kann gefordert sein!

          TokenIssuingResult tokenResult = null;
          if (_AuthService.TryValidateSessionIdAndCreateToken(clientId, sessionId, selectedScopes, out tokenResult)) {
            redirectUri = AppendUrlParam(redirectUri, tokenResult.ToString());
          }
          else {
            if(!string.IsNullOrWhiteSpace(tokenResult?.error)) {
              redirectUri = AppendUrlParam(redirectUri, "error", tokenResult.error, true);
            }
            else {
              redirectUri = AppendUrlParam(redirectUri, "error", "no-token", false);
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
          redirectUri = AppendUrlParam(redirectUri, "error", "unknown-response-type", false);
        }

        if (!string.IsNullOrWhiteSpace(state)) {
          redirectUri = AppendUrlParam(redirectUri, "state", state, false);
        }
        return this.Redirect(redirectUri);
      }
      catch (Exception ex) {
        SecLogger.LogCritical(ex);
        string errorPage = _AuthPageBuilder.GetErrorPage("Processing Error: " + ex.Message, viewOpt);
        return this.Content(errorPage, "text/html");
      }
    }

    private string AppendUrlParam(string url, string name, string value, bool escapeValue) {
      if (escapeValue) {
        value = HttpUtility.UrlEncode(value);
      }
      return AppendUrlParam( url, $"{name}={value}");
    }

    private string AppendUrlParam(string url, string nameAndAlreadyEscapedValue) {
      if (url.Contains("?")) {
        return url + $"&{nameAndAlreadyEscapedValue}";
      }
      else {
        return url + $"?{nameAndAlreadyEscapedValue}";
      }
    }

  }

}
