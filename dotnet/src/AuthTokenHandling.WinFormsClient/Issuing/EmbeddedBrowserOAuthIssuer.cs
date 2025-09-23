using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling")]

namespace Security.AccessTokenHandling.OAuth {

  /// <summary>
  /// INTERACTIVE-ISSUER!
  /// Will open an embedded browser window (Cef-Sharp based) to perform the auth flow.
  /// </summary>
  public class EmbeddedBrowserOAuthIssuer : IAccessTokenIssuer {

    public const string OfficialDummyRedirectUri = "urn:ietf:wg:oauth:2.0:oob";
    public const string LocalDummyRedirectUri = "http://127.0.0.1:20000";

    private string _ClientId;
    private string _ClientSecret;
    private IOAuthOperationsProvider _OAuthOperationsProvider = null;
    private Action<ClaimApprovalContext> _ClaimApprovalHandler = null;
    private IWin32Window _ParentWindow;
    private string _DummyRedirectUri;
    private string _GrantType;

    private bool _TryKeepBrowserInvisble;
    private bool _TryRequestIdToken;
    private bool _TryRequestRefreshToken;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="clientSecret"></param>
    /// <param name="oAuthOperationsProvider"></param>
    /// <param name="parentWindow"></param>
    /// <param name="dummyRedirectUrl"></param>
    /// <param name="grantType"></param>
    /// <param name="tryKeepBrowserInvisble">
    ///  tries to keep the browser invisible, until user interaction is required
    /// </param>
    /// <param name="tryRequestIdToken"></param>
    /// <param name="tryRequestRefreshToken"></param>
    /// <param name="claimApprovalHandler">
    /// This class implements 'IAccessTokenIssuer' in a way which allows callers to provide a set
    /// of claims to be requested. Use this hook to approve/customize these values on-the-fly.
    /// </param>
    public EmbeddedBrowserOAuthIssuer(
      string clientId,
      string clientSecret,
      IOAuthOperationsProvider oAuthOperationsProvider,
      IWin32Window parentWindow = null,
      string dummyRedirectUrl = null,
      string grantType = "code",
      bool tryRequestRefreshToken = false,
      bool tryRequestIdToken = false,
      bool tryKeepBrowserInvisble = false,
      Action<ClaimApprovalContext> claimApprovalHandler = null
    ) {

      _ClientId = clientId;
      _ClientSecret = clientSecret;
      _OAuthOperationsProvider = oAuthOperationsProvider;
      _ClaimApprovalHandler = claimApprovalHandler;
      _DummyRedirectUri = dummyRedirectUrl;
      _ParentWindow = parentWindow;
      _GrantType = grantType.ToLower();
      _TryKeepBrowserInvisble = tryKeepBrowserInvisble;
      _TryRequestIdToken = tryRequestIdToken;
      _TryRequestRefreshToken = tryRequestRefreshToken;

      if (_GrantType == "code") {
      }
      else if (_GrantType == "implicit") {
      }
      else {
        throw new NotImplementedException($"Unknown grant_type '{_GrantType}'!");
      }

      if (string.IsNullOrWhiteSpace(_DummyRedirectUri)) {
        _DummyRedirectUri = LocalDummyRedirectUri;
      }

    }

    bool IAccessTokenIssuer.TryRequestAccessToken(out TokenIssuingResult result) {
      return ((IAccessTokenIssuer)this).TryRequestAccessToken(null, out result);
    }

    bool IAccessTokenIssuer.TryRequestAccessToken(
      Dictionary<string, object> claimsToRequest, out TokenIssuingResult result
    ) {

      //values for this vars will be extracted from claimsToRequest
      string[] scopesToRequest = null;
      string state = null;
      string redirectUri = null;

      Dictionary<string, object> additionalClaimsToUse = ClaimApprovalContext.ProcessRequestedClaims(
        claimsToRequest,
        _ClaimApprovalHandler ?? ((c)=> c.TakeOverAllRequestedClaims()),
        (c)=> {
          //afterwards some preprocessing, dedicated to our concrete implementation...
          
          //these params have to be passed as separate parameter into the issuing merthod:
          if (c.TryGetScopeExpressionsToUseAsArray(out string[] expressions)) {
            scopesToRequest = expressions;
          }
          if(c.ClaimsToUse.TryGetValue("state", out object stateRaw)) {
            state = (stateRaw as string);
          }
          if (c.ClaimsToUse.TryGetValue("redirect_uri", out object redirectUriRaw)) {
            redirectUri = (redirectUriRaw as string);
            c.ClaimsToUse.Remove("redirect_uri");
          }

          c.RemoveFromClaimsToUseIfPresent("scope", "state", "redirect_uri", "client_id", "client_secret");
        }
      );

      if(string.IsNullOrWhiteSpace(state)) {
        state = Random.Shared.NextInt64().ToString("x16");
      }
      if (string.IsNullOrWhiteSpace(redirectUri)) {
        redirectUri = _DummyRedirectUri;
      }

      string entryUrl;
      if (_GrantType == "code") {

        entryUrl = _OAuthOperationsProvider.GenerateEntryUrlForOAuthCodeGrant(
          _ClientId,
          redirectUri,
          _TryRequestRefreshToken,
          _TryRequestIdToken,
          state,
          scopesToRequest,
          additionalClaimsToUse
        );

      }
      else if (_GrantType == "implicit") {
#pragma warning disable CS0618

        entryUrl = _OAuthOperationsProvider.GenerateEntryUrlForOAuthImplicitGrant(
          _ClientId,
          redirectUri,
          _TryRequestRefreshToken,
          _TryRequestIdToken,
          state,
          scopesToRequest,
          additionalClaimsToUse
        );

#pragma warning restore
      }
      else {
        throw new NotImplementedException($"Unknown grant_type '{_GrantType}'!");
      }

      using (AuthForm dlg = this.CreateDialog(
         entryUrl, _DummyRedirectUri,
         windowTitle: $"Login ({_OAuthOperationsProvider.ProviderDisplayTitle})",
         secondsToWaitBeforeShowing: (_TryKeepBrowserInvisble ? 4 : 0)
      )) {

        dlg.Icon = _OAuthOperationsProvider.GetProviderIcon();

        if (_ParentWindow != null) {
          dlg.ShowDialog(_ParentWindow);
        }
        else {
          dlg.ShowDialog();
        }

        bool success = _OAuthOperationsProvider.TryGetTokenFromRedirectedUrl(
          dlg.CurrentUrl, _ClientId, _ClientSecret, out result
        );

        return success;
      }

    }

    #region " Helpers "

    private AuthForm CreateDialog(
      string entryUrl, string returnUrl,
      int windowWidth = 0, int windowHeight = 0, string windowTitle = "Login",
      int secondsToWaitBeforeShowing = 0
    ) {
      AuthForm dlg = new AuthForm();

      dlg.Text = windowTitle;
      dlg.CurrentUrl = entryUrl;
      dlg.ReturnOn = returnUrl;

      dlg.SecondsToWaitBeforeShowing = secondsToWaitBeforeShowing;
      dlg.Opacity = 0.99;
      dlg.WindowState = FormWindowState.Minimized;

      Rectangle wa = Screen.PrimaryScreen.WorkingArea;
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

      return dlg;
    }

    private static int GetFreePort() {

      // Listener auf Port 0 -> OS wählt freien Port
      TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
      try {
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
      }
      finally {
#if NET8_0_OR_GREATER
        listener.Dispose();
#endif
      }

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

    // Returns custom query parameters as string of param name - value pairs WITH & IN FRONT!!!
    // Example: &view_mode=3&login_hith=WINAUTH
    private static string SerializeCustomQueryParameters(Dictionary<string, string> customQueryParameters) {
      var parsedCustomQueryParameters = string.Empty;

      if (customQueryParameters == null)
        return parsedCustomQueryParameters;

      foreach (var customQueryParameter in customQueryParameters) {
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

    #endregion

  }

}
