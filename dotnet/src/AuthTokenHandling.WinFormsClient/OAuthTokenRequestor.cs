//using CefSharp.DevTools.Database;
//using CefSharp.DevTools.DOM;
//using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Security.AccessTokenHandling {

  public class OAuthTokenRequestor {

    private string _ClientId;
    private string _ClientSecret;
    private string _AuthorizeUrl;
    private string _RetrievalUrl;
    private string _RedirectUrl;

    public OAuthTokenRequestor(
      string clientId,
      string clientSecret,
      string authorizeUrl,
      string retrievalUrl,
      string redirectUrl = "https://localhost"
    ) {
      _ClientId = clientId;
      _ClientSecret = clientSecret;
      _AuthorizeUrl = authorizeUrl;
      _RetrievalUrl = retrievalUrl;
      _RedirectUrl = redirectUrl;

      if (_AuthorizeUrl.Contains("?")) {
        _AuthorizeUrl = _AuthorizeUrl + "&";
      }
      else {
        _AuthorizeUrl = _AuthorizeUrl + "?";
      }

    }

    public bool TrySilentAuthViaCodeGrand(
      string returnUrl, string state, string scopeToRequest,
      string loginHint, out string retrievedCode,
      Dictionary<string, string> customQueryParameters = null
    ) { 
      try {
        var additionalQueryParameters = SerializeCustomQueryParameters(customQueryParameters);

        string url = $"{_AuthorizeUrl}response_type=code&redirect_uri={returnUrl}&state={state}&scope={scopeToRequest}&login_hint={loginHint}&client_id={_ClientId}{additionalQueryParameters}";
        string result = this.GetFinalRedirect(url, returnUrl);

        retrievedCode = this.PickFromUrl(result, "code");

        if (!string.IsNullOrWhiteSpace(retrievedCode)) {
          return true;
        }

      }
      catch (Exception ex) {
      }
      retrievedCode = null;
      return false;
    }

    private string GetFinalRedirect(string url, string endUrl) {
      if (string.IsNullOrWhiteSpace(url))
        return url;

      int maxRedirCount = 8;  // prevent infinite loops
      string newUrl = url;
      do {
        HttpWebRequest req = null;
        HttpWebResponse resp = null;
        try {
          if (url.StartsWith(endUrl) & (url.Contains("?code=") || url.Contains("?token="))) {
            return url;
          }
          req = (HttpWebRequest)HttpWebRequest.Create(url);
          req.Method = "GET";
          req.AllowAutoRedirect = false;
          req.UseDefaultCredentials = true;
          resp = (HttpWebResponse)req.GetResponse();
          switch (resp.StatusCode) {
            case HttpStatusCode.OK:
              return newUrl;
            case HttpStatusCode.Redirect:
            case HttpStatusCode.MovedPermanently:
            case HttpStatusCode.RedirectKeepVerb:
            case HttpStatusCode.RedirectMethod:
              newUrl = resp.Headers["Location"];
              if (newUrl == null)
                return url;

              if (newUrl.IndexOf("://", System.StringComparison.Ordinal) == -1) {
                // Doesn't have a URL Schema, meaning it's a relative or absolute URL
                Uri u = new Uri(new Uri(url), newUrl);
                newUrl = u.ToString();
              }
              break;
            default:
              return newUrl;
          }
          url = newUrl;
        }
        catch (WebException ex) {
          // Return the last known good URL
          return newUrl;
        }
        catch (Exception ex) {
          return newUrl;
        }
        finally {
          if (resp != null)
            resp.Close();
        }
      } while (maxRedirCount-- > 0);

    return newUrl;
  }

  //https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type
  public bool TryBrowserAuthViaCodeGrand(IWin32Window windowOwner,
      string returnUrl, string state, string scopeToRequest, string loginHint,
      out string retrievedCode,
      int windowWidth = 0, int windowHeight = 0, string windowTitle = "Login",
      Dictionary<string, string> customQueryParameters = null
      ) {
      var additionalQueryParameters = SerializeCustomQueryParameters(customQueryParameters);

      using (var dlg = new AuthForm()) {
        dlg.Url = $"{_AuthorizeUrl}response_type=code&redirect_uri={returnUrl}&state={state}&scope={scopeToRequest}&login_hint={loginHint}&client_id={_ClientId}{additionalQueryParameters}";
        dlg.ReturnOn = returnUrl;

        dlg.Text = windowTitle;
        var wa = Screen.PrimaryScreen.WorkingArea;
        if (windowWidth < 50) {
          dlg.Left = wa.Left + 100;
          dlg.Width = wa.Width - 200;
        }
        else {
          dlg.Left = (wa.Width - windowWidth) / 2;
          dlg.Width = windowWidth;
        }
        if (windowHeight < 50) {
          dlg.Top = wa.Top + 100;
          dlg.Height = wa.Height - 200;
        }
        else {
          dlg.Top = (wa.Height - windowHeight) / 2;
          dlg.Height = windowHeight;
        }
        dlg.StartPosition = FormStartPosition.CenterScreen;

        dlg.ShowDialog(windowOwner);
        string code = null;
        if (dlg.Url.StartsWith(returnUrl, StringComparison.InvariantCultureIgnoreCase)) {
          code = this.PickFromUrl(dlg.Url, "code");
        }
        if (string.IsNullOrWhiteSpace(code)) {
          retrievedCode = string.Empty;
          return false;
        }
        else {
          retrievedCode = code;
          return true;
        }
      }
    }

    //https://developer.okta.com/blog/2019/05/01/is-the-oauth-implicit-flow-dead

    /// <summary>
    /// 
    /// </summary>
    /// <param name="windowOwner"></param>
    /// <param name="returnUrl"></param>
    /// <param name="state"></param>
    /// <param name="scopeToRequest"></param>
    /// <param name="loginHint"></param>
    /// <param name="accessToken"></param>
    /// <param name="refreshToken">OPTIONAL (can be null, if non was received)</param>
    /// <param name="idToken">OPTIONAL (can be null, if non was received)</param>
    /// <param name="windowWidth"></param>
    /// <param name="windowHeight"></param>
    /// <param name="windowTitle"></param>
    /// <param name="customQueryParameters"></param>
    /// <returns></returns>
    public bool TryBrowserAuthViaImplicitGrand(IWin32Window windowOwner,
      string returnUrl, string state, string scopeToRequest, string loginHint, 
      out string accessToken, out string refreshToken, out string idToken,
      int windowWidth = 0, int windowHeight = 0, string windowTitle = "Login",
      Dictionary<string, string> customQueryParameters = null
      ) {

      var additionalQueryParameters = SerializeCustomQueryParameters(customQueryParameters);

      using (var dlg = new AuthForm()) {
        dlg.Url = $"{_AuthorizeUrl}response_type=token&redirect_uri={returnUrl}&state={state}&scope={scopeToRequest}&login_hint={loginHint}&client_id={_ClientId}{additionalQueryParameters}";
        dlg.ReturnOn = returnUrl;

        dlg.Text = windowTitle;
        var wa = Screen.PrimaryScreen.WorkingArea;
        if (windowWidth < 50) {
          dlg.Left = wa.Left + 100;
          dlg.Width = wa.Width - 200;
        }
        else {
          dlg.Left = (wa.Width - windowWidth) / 2;
          dlg.Width = windowWidth;
        }
        if (windowHeight < 50) {
          dlg.Top = wa.Top + 100;
          dlg.Height = wa.Height - 200;
        }
        else {
          dlg.Top = (wa.Height - windowHeight) / 2;
          dlg.Height = windowHeight;
        }
        dlg.StartPosition= FormStartPosition.CenterScreen;

        dlg.ShowDialog(windowOwner);

        string token = null;
        if (dlg.Url.StartsWith(returnUrl, StringComparison.InvariantCultureIgnoreCase)) {
          token = this.PickFromUrl(dlg.Url, "access_token");
          refreshToken = this.PickFromUrl(dlg.Url, "refresh_token");
          idToken = this.PickFromUrl(dlg.Url, "id_token");
          //? = this.PickFromUrl(dlg.Url, "token_type");
          //? = this.PickFromUrl(dlg.Url, "expires_in");
          string error = this.PickFromUrl(dlg.Url, "error");
        }
        if (string.IsNullOrWhiteSpace(token)) {
          accessToken = string.Empty;
          idToken = null;
          refreshToken = null;
          return false;
        }
        else {
          accessToken = token;
          idToken = null;
          refreshToken = null;
          return true;
        }
      }
    }

    // Returns custom query parameters as string of param name - value pairs WITH & IN FRONT!!!
    // Example: &view_mode=3&login_hith=WINAUTH
    private static string SerializeCustomQueryParameters(Dictionary<string, string> customQueryParameters)
    {
      var parsedCustomQueryParameters = string.Empty;

      if (customQueryParameters == null)
        return parsedCustomQueryParameters;

      foreach (var customQueryParameter in customQueryParameters)
      {
        parsedCustomQueryParameters += $"&{customQueryParameter.Key}={customQueryParameter.Value}";
      }

      return parsedCustomQueryParameters;
    }

    private string PickFromUrl(string url, string key) {
      return (
        (url + "?").
        Split('?')[1].
        Split('&').
        Where((x) => x.StartsWith(key + "=", StringComparison.CurrentCultureIgnoreCase)).
        Select((x) => x.Substring(x.IndexOf("=") + 1)).
        FirstOrDefault()
      );
    }

    public bool TryRetrieveTokenViaCode(string code, out string retrievedToken) {
      return this.TryRetrieveTokenViaCode(code, false, out retrievedToken);
    }

    public bool TryRetrieveTokenViaCode(string authorizationCode, bool useHttpGet, out string retrievedToken) {
      return this.TryRetrieveTokenViaCode(authorizationCode, useHttpGet, out retrievedToken, out var errorBufferDummy);
    }

    public bool TryRetrieveTokenViaCode(string authorizationCode, bool useHttpGet, out string retrievedToken, out string error) {
      return this.TryRetrieveTokenViaCode(
        authorizationCode, useHttpGet,
        out retrievedToken, out string refreshTokenDummy, out string idTokenDummy,
        out error
      );
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationCode"></param>
    /// <param name="useHttpGet"></param>
    /// <param name="accessToken"></param>
    /// <param name="refreshToken">OPTIONAL (can be null, if non was received)</param>
    /// <param name="idToken">OPTIONAL (can be null, if non was received)</param>
    /// <param name="error"></param>
    /// <returns></returns>
    public bool TryRetrieveTokenViaCode(
      string authorizationCode, bool useHttpGet,
      out string accessToken, out string refreshToken, out string idToken,
      out string error
    ) {
      try {
        using (WebClient wc = new WebClient()) {
          //HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
          wc.UseDefaultCredentials = true;

          string formEncodedData = "client_id=" + _ClientId + "&client_secret=" + _ClientSecret + "&code=" + authorizationCode +
            "&grant_type=authorization_code&redirect_uri=" + _RedirectUrl;

          string rawJsonResponse;

          wc.Headers.Set("Accept", "application/json");
          if (!useHttpGet) {
            wc.Headers.Set("Content-Type", "application/x-www-form-urlencoded");
            //wc.Headers.Set("Access-Control-Allow-Origin", window.location.origin);
            //wc.Headers.Set("Referrer-Policy", 'origin-when-cross-origin');
            rawJsonResponse = wc.UploadString(_RetrievalUrl, formEncodedData);
          }
          else {
            rawJsonResponse = wc.DownloadString(_RetrievalUrl + "?" + formEncodedData);
          }

          refreshToken = null;
          idToken = null;
          accessToken = this.PickJsonValue("access_token", rawJsonResponse);
          if (string.IsNullOrWhiteSpace(accessToken)) {
            accessToken = null;
            error = this.PickJsonValue("error_description", rawJsonResponse);
            if (string.IsNullOrWhiteSpace(error)) {
              error = this.PickJsonValue("error", rawJsonResponse);
            }
            if (!string.IsNullOrWhiteSpace(error)) {
              error = "No token received! Server says: " + error;
            }
            else {
              error = "No token received!";
            }
            return false;
          }
          else {
            idToken = this.PickJsonValue("id_token", rawJsonResponse);
            refreshToken = this.PickJsonValue("refresh_token", rawJsonResponse);
          }
          error = null;
          return true;

        }
      }
      catch (Exception ex) {
        accessToken = null;
        refreshToken = null;
        idToken = null;
        error = "Exception on client side: " + ex.Message;
        return false;
      }

    }

    //HACK: handgedengelt, daf�r brauchen wir keine lib wie newtonsoft...
    private string PickJsonValue(string key,string rawJson) {
      int foundAt = rawJson.IndexOf("\""+ key + "\":");
      if (foundAt >= 0) {
        string startsWithvalue = rawJson.Substring(foundAt + key.Length + 3).Trim();
        if (startsWithvalue.StartsWith("null")) {
          return null;
        }
        else if (startsWithvalue.StartsWith("\"")) {
          return startsWithvalue.Substring(1, startsWithvalue.IndexOf("\"", 1) - 1);
        }
        else if (startsWithvalue.StartsWith("{")) {
          return null;
        }
        else if (startsWithvalue.StartsWith("[")) {
          return null;
        }
        else { //number
          startsWithvalue = startsWithvalue.Replace("}", ",").Replace(Environment.NewLine,"");
          return startsWithvalue.Substring(0, startsWithvalue.IndexOf(",", 1));
        }
      }
      else {
        return null;
      }
    }

  }

}
