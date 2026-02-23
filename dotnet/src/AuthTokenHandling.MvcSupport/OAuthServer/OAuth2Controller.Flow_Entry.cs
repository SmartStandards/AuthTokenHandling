using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling")]

namespace Security.AccessTokenHandling.OAuth.Server {

  [ApiController]
  [ApiExplorerSettings(GroupName = "OAuth")]
  [Route("oauth2")]
  internal partial class OAuth2Controller : ControllerBase {

    private readonly ILogger<OAuth2Controller> _Logger;
    private readonly IOAuthService _AuthService;
    private readonly IAuthPageBuilder _AuthPageBuilder;

    //TODO: viewmode umbenennen u splitten (promt/consent/embedded/darkmode/...)
    //TODO: otp sauber in sessionid umbenennen

    public OAuth2Controller(
      ILogger<OAuth2Controller> logger, IOAuthService authService, IAuthPageBuilder authPageBuilder
    ) {
      _Logger = logger;
      _AuthService = authService;
      _AuthPageBuilder = authPageBuilder; 
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // AUTHORIZE STEP #1 - BROWSER LANDING (HTTP-GET)                                                //
    ///////////////////////////////////////////////////////////////////////////////////////////////////


    [Route("sso/authorize")]
    [Authorize(Policy = "WindowsOnly")]
    [HttpGet(), Produces("text/html")]
    public ActionResult GetLogonPageSso(
      [FromQuery(Name = "response_type")] string responseType,
      [FromQuery(Name = "client_id")] string clientId,
      [FromQuery(Name = "redirect_uri")] string redirectUri,
      [FromQuery(Name = "state")] string state,
      [FromQuery(Name = "scope")] string rawScopePreference,
      [FromQuery(Name = "login_hint")] string loginHint,
      [FromQuery(Name = "err")] string errorMessagePassedViaQueryString,
      [FromQuery(Name = "otp")] string sessionId,
      [FromQuery(Name = "view_mode")] int viewMode,
      [FromQuery(Name = "code")] string codeFromDelegate //NUR WENN EIN DELEGATE DAZWISCHEN HING
    ) {

      if (!this.TryGetPasstroughUserIdentity(out string winUserName)) { 
        return Challenge("Negotiate");
      }

      return GetLogonPage(
        responseType, clientId, redirectUri, state, rawScopePreference, "pass-trough",
        errorMessagePassedViaQueryString, sessionId, viewMode, codeFromDelegate
      );

    }

    [Route("authorize")]
    [HttpGet(), Produces("text/html")]
    [AllowAnonymous]
    public ActionResult GetLogonPage(
      [FromQuery(Name = "response_type")] string responseType,
      [FromQuery(Name = "client_id")] string clientId,
      [FromQuery(Name = "redirect_uri")] string redirectUri,
      [FromQuery(Name = "state")] string state,
      [FromQuery(Name = "scope")] string rawScopePreference,
      [FromQuery(Name = "login_hint")] string loginHint,
      [FromQuery(Name = "err")] string errorMessagePassedViaQueryString,
      [FromQuery(Name = "otp")] string sessionId,
      [FromQuery(Name = "view_mode")] int viewMode,
      [FromQuery(Name = "code")] string codeFromDelegate //NUR WENN EIN DELEGATE DAZWISCHEN HING
    ) {

      Uri thisUri = new Uri(HttpContext.Request.GetDisplayUrl());
      HostString apiCallerHost = this.HttpContext.Request.Host;

      AuthPageViewModeOptions viewOpt = new AuthPageViewModeOptions();
      viewOpt.LowSpaceEmbedded = (viewMode == 2);

      try {

        if (string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(codeFromDelegate)) {
          // the only exception where clientId can be empty is when we are
          // returning from a delegated authorization -> will be done later (after decoding state)
        }
        else {
          //normally VALIDATE clientId first...
          if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out string msg)) {
            string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewOpt);
            return this.Content(errorPage, "text/html");
          }
        }
  
        ///////////////////////////////////////////////////////////////////////////////////////////////////

        //ROUNDTRIP - DELEGATION TO ANOTHER OAUTH SERVER ???
        #region " IOAuthServiceWithDelegation "

        //this is an addition extended feature to support delegation to another oauth server
        if (_AuthService is IOAuthServiceWithDelegation && String.IsNullOrWhiteSpace(sessionId)) {

          // WE ARE JUST RETURNING FROM THE DELEGATED AUTHORIZATION  
          if (!string.IsNullOrWhiteSpace(codeFromDelegate)) {
            try {

              //STATE muss dann auch da sein!
              string stateBagJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(state));
              StateBag deserializedStateBag = JsonConvert.DeserializeObject<StateBag>(stateBagJson);

              if(string.IsNullOrWhiteSpace(clientId)) {
                clientId = deserializedStateBag.OriginalClientId;
              }

              if (((IOAuthServiceWithDelegation)_AuthService).TryHandleCodeflowDelegationResult(
                codeFromDelegate, deserializedStateBag.SessionId, thisUri.GetLeftPart(UriPartial.Path)
              )) {

                //This ensures that we are now considered authenticated and go directly to the scope selection
                sessionId = deserializedStateBag.SessionId;

                responseType = deserializedStateBag.OriginalResponseType;
                clientId = deserializedStateBag.OriginalClientId;
                redirectUri = deserializedStateBag.OriginalRedirectUri;
                state = deserializedStateBag.OriginalState;
                rawScopePreference = deserializedStateBag.OriginalScope;
                viewMode = deserializedStateBag.ViewMode;
        
                if (!_AuthService.TryValidateApiClient(clientId, apiCallerHost.Host, redirectUri, out string msg)) {
                  string errorPage = _AuthPageBuilder.GetErrorPage(msg, viewOpt);
                  return this.Content(errorPage, "text/html");
                }

              }
              else {
                throw new Exception($"{nameof(IOAuthServiceWithDelegation.TryHandleCodeflowDelegationResult)} returned false!");
              }
            }
            catch (Exception ex2){
              string msgs = "Invalid State on return from Delegate";
              SecLogger.LogError(ex2.Wrap(msgs));
              //TODO: information-hiding!!!
              string errorPage = _AuthPageBuilder.GetErrorPage(msgs, viewOpt);
              return this.Content(errorPage, "text/html");
            }

          } // WE ARE CHECKING IF A DELEGATED AUTHORIZATION SHOULD BE STARTED
          else if (((IOAuthServiceWithDelegation)_AuthService).CodeFlowDelegationRequired(
            clientId, ref loginHint,
            out string targetAuthorizeUrl, out string targetClientId, out sessionId
          )) {


            StateBag stateBag = new StateBag {
              OriginalState = state,
              SessionId = sessionId,
              OriginalRedirectUri = redirectUri,
              OriginalScope = rawScopePreference,
              OriginalResponseType = responseType,
              OriginalClientId = clientId,
              ViewMode = viewMode
            };

            string stateBagJson = JsonConvert.SerializeObject(stateBag);
            string b64StateBag = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(stateBagJson));


            targetAuthorizeUrl = (
              targetAuthorizeUrl.
              SetQueryParam("response_type", "code"). //hardcoded for the "delegation"-feature
              SetQueryParam("client_id", targetClientId).
              SetQueryParam("redirect_uri", thisUri.GetLeftPart(UriPartial.Path), true).
              SetQueryParam("state", b64StateBag)
            );

            SecLogger.LogTrace(2083109404818208602L, 0, $"Delegating OAuth-Code-Flow to '{targetAuthorizeUrl}'");
            return this.Redirect(targetAuthorizeUrl);

          }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        if (string.IsNullOrWhiteSpace(responseType)) {
          string errorPage = _AuthPageBuilder.GetErrorPage("Url-param 'response_type' is missing! Please provide one ('code'/'token'/'display'/...)", viewOpt);
          return this.Content(errorPage, "text/html");
        }

        //dont propmt for anything while trying pass-trough unattended...
        bool pseudoUnattendedMode = (viewMode == 3); //TODO: umbau auf standardisierte "promt/consent" parameter!!!

        ScopeDescriptor[] availableScopes = null;
        string authFormTemplate;
        if (String.IsNullOrWhiteSpace(sessionId)) {

          ///////////////////////////////////////////////////////////////////////////////////////////////////
          // NO SESSION YET - AUTHENTICATION PAHSE (identity required!)

          #region " WINDOWS Pass-Trough "

          string winUserName = null;

          if (loginHint == "pass-trough" || loginHint == "WINAUTH") {

            //Authorize-Attribut über der methode nötig!!!
            if (!Request.GetDisplayUrl().Contains("sso")) {

              //return Challenge("Negotiate");
              return this.Redirect("sso/authorize" + Request.QueryString);
            }

            loginHint = string.Empty;

            if (this.TryGetPasstroughUserIdentity(out winUserName)) {

              if (pseudoUnattendedMode && !String.IsNullOrWhiteSpace(winUserName)) {

                string[] selectedScopes = rawScopePreference.Split(' ');
                bool logonSuccess = _AuthService.TryAuthenticate(
                  clientId, winUserName, null, true, state, out sessionId, out string step1Msg
                );

                if (!logonSuccess) {
                  string err = $"Silent Pass-trough authentication for '{winUserName}' failed: {step1Msg}";
                  SecLogger.LogError(2079844630286309066L, 73004, err);

                  return this.Redirect(
                    redirectUri.AppendQueryParam("error", err, true).AppendQueryParam("state", state)
                  );
                }

                bool codeCreationSuccess = _AuthService.TryValidateSessionIdAndCreateRetrievalCode(
                  clientId, sessionId, selectedScopes, out string code, out string step2Msg
                );

                if (!codeCreationSuccess) {
                  string err = $"Silent Pass-trough authentication for '{winUserName}' failed: {step2Msg}";
                  SecLogger.LogError(2079844869748849906L, 73004, err);

                  return this.Redirect(
                    redirectUri.AppendQueryParam("error", err, true).AppendQueryParam("state", state)
                  );
                }

                return this.Redirect(
                  redirectUri.AppendQueryParam("code", code).AppendQueryParam("state", state)
                );

              }

            }
            else {
              string err = $"Pass-trough authentication requested, but no windows identity could be evaluated!";
              SecLogger.LogError(2079844630286309066L, 73003, err);

              if (pseudoUnattendedMode) {
                return this.Redirect(
                  redirectUri.AppendQueryParam("error", err, true).AppendQueryParam("state", state)
                );
              }//otherwise, the user can still enter credentials manually...

            }

          }

          ///////////////////////////////////////////////////////////////////////////////////////////////////
          #endregion

          if (!string.IsNullOrWhiteSpace(errorMessagePassedViaQueryString)) {
            //HACK: hier darf natürlich kein html sein!
            errorMessagePassedViaQueryString = $"<p><span style=\"color: red\">{errorMessagePassedViaQueryString}</span><p>";
          }
          else {
            errorMessagePassedViaQueryString = "";
          }

          if (!String.IsNullOrWhiteSpace(winUserName)) {
            authFormTemplate = _AuthPageBuilder.GetWinAuthForm(
              responseType, "Please confirm pass-trough credentials:",
              winUserName, state, clientId, redirectUri, rawScopePreference, viewOpt, errorMessagePassedViaQueryString
            );
          }
          else {
            authFormTemplate = _AuthPageBuilder.GetAuthForm(
              responseType, "Please enter your credentials:",
              loginHint, state, clientId, redirectUri, rawScopePreference, viewOpt, errorMessagePassedViaQueryString
            );


            //SSO VORSCHLAG (nur ein Angebot in From eines links)
            if (!Request.GetDisplayUrl().Contains("sso")) {
              authFormTemplate = authFormTemplate.Replace(
                 "</body>", $"<a href=\"sso/authorize{Request.QueryString}\">Use Single-Sign-On (pass-trough)</a></body>"
              );
            }


          }

        }
        else {
          ///////////////////////////////////////////////////////////////////////////////////////////////////
          // SESSION AVAILABLE - AUTHORIZATION PAHSE (promt for scopes consent)

          string[] prefferredScopes;
          if (rawScopePreference != null) {
            prefferredScopes = rawScopePreference.Split(' ').Where((s) => !String.IsNullOrWhiteSpace(s)).ToArray();
          }
          else {
            prefferredScopes = new string[] { };
          }

          if (!_AuthService.TryGetAvailableScopesBySessionId(clientId, sessionId, prefferredScopes, out availableScopes, out string msg2)) {
            string errorPage = _AuthPageBuilder.GetErrorPage(msg2, viewOpt);
            return this.Content(errorPage, "text/html");
          }
          else {

            if (!string.IsNullOrWhiteSpace(errorMessagePassedViaQueryString)) {
              //HACK: natürlich darf hier kein html sein
              errorMessagePassedViaQueryString = $"<p><span style=\"color: red\">{errorMessagePassedViaQueryString}</span><p>";
            }
            else {
              errorMessagePassedViaQueryString = "";
            }

            authFormTemplate = _AuthPageBuilder.GetScopeConfirmationForm(
              responseType, "Please select the access scopes to be granted:",
              sessionId, state, clientId, redirectUri, rawScopePreference, availableScopes, viewOpt, errorMessagePassedViaQueryString
            );

          }
        }

        return this.Content(authFormTemplate, "text/html", Encoding.UTF8);
      }
      catch (Exception ex) {
        SecLogger.LogCritical(ex);
        string errorPage = _AuthPageBuilder.GetErrorPage("Processing Error: " + ex.Message, viewOpt);
        return this.Content(errorPage, "text/html");
      }
    }

  }

}
