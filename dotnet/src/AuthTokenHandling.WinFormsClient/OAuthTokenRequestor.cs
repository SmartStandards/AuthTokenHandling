using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
//using System.Reflection.Metadata;
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
  }

    //https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type
    public bool TryBrowserAuthViaCodeGrand(IWin32Window windowOwner,
      string returnUrl, string state, string scopeToRequest, string loginHint, out string retrievedCode, 
      int windowWidth = 0, int windowHeight = 0, string windowTitle = "Login"
      ) {
      using (var dlg = new AuthForm()) {
        dlg.Url = $"{_AuthorizeUrl}?response_type=code&redirect_uri={returnUrl}&state={state}&scope={scopeToRequest}&login_hint={loginHint}&client_id={_ClientId}";
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
          code = (
            (dlg.Url + "?").
            Split('?')[1].
            Split('&').
            Where((x) => x.StartsWith("code=", StringComparison.CurrentCultureIgnoreCase)).
            Select((x) => x.Substring(x.IndexOf("=") + 1)).
            FirstOrDefault()
          );

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
    public bool TryBrowserAuthViaImplicitGrand(IWin32Window windowOwner,
      string returnUrl, string state, string scopeToRequest, string loginHint, out string retrievedToken,
      int windowWidth = 0, int windowHeight = 0, string windowTitle = "Login"
      ) {
      using (var dlg = new AuthForm()) {
        dlg.Url = $"{_AuthorizeUrl}?response_type=token&redirect_uri={returnUrl}&state={state}&scope={scopeToRequest}&login_hint={loginHint}&client_id={_ClientId}";
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
          token = (
              (dlg.Url + "?").
              Split('?')[1].
              Split('&').
              Where((x) => x.StartsWith("token=", StringComparison.CurrentCultureIgnoreCase)).
              Select((x) => x.Substring(x.IndexOf("=") + 1)).
              FirstOrDefault()
            );

          }
          if (string.IsNullOrWhiteSpace(token)) {
            retrievedToken = string.Empty;
            return false;
          }
          else {
            retrievedToken = token;
            return true;
          }
        }
      }

    public bool TryRetrieveTokenViaCode(string code, out string retrievedToken) {
      return this.TryRetrieveTokenViaCode(code, false, out retrievedToken);
    }

    public bool TryRetrieveTokenViaCode(string authorizationCode, bool useHttpGet, out string retrievedToken) {
      try {
        using (WebClient wc = new WebClient()) {

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

          retrievedToken = this.PickJsonValue("access_token", rawJsonResponse);
          if (string.IsNullOrWhiteSpace(retrievedToken)) {
            retrievedToken = null;
            string error = this.PickJsonValue("error", rawJsonResponse);
            return false;
          }
          return true;

        }
      }
      catch (Exception ex) {
        retrievedToken = null;
        return false;
      }

    }

    //HACK: handgedengelt, dafür brauchen wir keine lib wie newtonsoft...
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
