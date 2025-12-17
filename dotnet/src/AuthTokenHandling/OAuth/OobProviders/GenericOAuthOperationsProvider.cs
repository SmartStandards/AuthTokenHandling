using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.WebSockets;

namespace Security.AccessTokenHandling.OAuth.OobProviders {

  public class GenericOAuthOperationsProvider : IOAuthOperationsProvider, IDisposable {

    #region " Matadata & Config "

    private const string _DefaultIconUrl = "data:image/png;base64,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";

    private Dictionary<string, string> Configuration { get; } = new Dictionary<string, string>();

    public void SetConfigurationValue(string key, string value) {
      if(value == null) {
        value = string.Empty;
      }    
      this.Configuration[key] = value;  
      if (_ClientInvalidatingSettingNames.Contains(key)) {
        this.Dispose();
      }
    }
    public bool TryGetConfigurationValue(string key, out string value) {
      return this.Configuration.TryGetValue(key, out value);
    }

    public string ProviderInvariantName {
      get { return "generic"; }
    }

    public string ProviderDisplayTitle {
      get {
        if (this.Configuration.TryGetValue("provider_display_title", out string configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return "OAuth 2.0";
      }
    }

    public string ProviderIconUrl {
      get {
        if (this.Configuration.TryGetValue("provider_icon_url", out string configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return _DefaultIconUrl;
      }
    }

    private bool ClientCredentialsViaBasicAuth {
      get {
        if (this.TryGetConfigurationValue("client_credentials_via_basicauth", out string settingValue)) {
          return IsTrue(settingValue);
        }
        return false;
      }
    }

    /// <summary></summary>
    /// <param name="capabilityName">
    /// Wellknown capabilities are:
    ///   "introspection"
    ///   "refresh_token"
    ///   "id_token"
    ///   "darkmode_url_param"
    ///   "iframe_allowed"
    /// </param>
    public bool HasCapability(string capabilityName) {

      if (capabilityName == "introspection") {
        if(this.TryGetConfigurationValue("introspection_endpoint", out string introspectionEndpoint)) {
          if (!String.IsNullOrWhiteSpace(introspectionEndpoint)) {
            return true;
          }
        }
        return false;
      }

      if (this.Configuration.TryGetValue("supports_" + capabilityName, out string configuredValue) && !string.IsNullOrWhiteSpace(configuredValue)) {
        if (configuredValue.Equals("true", StringComparison.CurrentCultureIgnoreCase) || configuredValue == "1") {
          return true;
        }
      };

      return false;
    }

    #endregion

    #region " HttpClient (Lazy) "

    public Func<IOAuthOperationsProvider, HttpClient> HttpClientFactory { get; set; }

    private HttpClient _HttpClient = null;

    private HttpClient HttpClient {
      get {
        if (_HttpClient == null) {
          _HttpClient = HttpClientFactory != null ? HttpClientFactory.Invoke(this) : OAuthOperationsProviderCommonSetupHelper.DefaultHttpClientFactory(this);
        }
        return _HttpClient;
      }
    }

    private static string[] _ClientInvalidatingSettingNames = {
      "retrieve_with_default_credentials"
    };

    public void Dispose() {
      if (_HttpClient != null) {
        _HttpClient.Dispose();
      }
    }

    #endregion

    public GenericOAuthOperationsProvider()
      : this(OAuthOperationsProviderCommonSetupHelper.DefaultHttpClientFactory) {
    }

    public GenericOAuthOperationsProvider(Func<IOAuthOperationsProvider,HttpClient> httpClientFactory) {
      this.HttpClientFactory = httpClientFactory;

      // Sinnvolle, generische Defaults (alles überschreibbar):
      var cfg = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

      cfg["authorization_endpoint"] = "";
      cfg["provider_display_title"] = "Generic OAuth 2.0";
      cfg["token_endpoint"] = "";
      cfg["supports_refresh_token"] = "true";
      cfg["supports_id_token"] = "false";
      // Unterstützt sowohl "introspection_endpoint" (neu) als auch "tokeninfo_endpoint" (Kompatibilität)
      cfg["introspection_endpoint"] = "";
      cfg["tokeninfo_endpoint"] = "";
      cfg["userinfo_endpoint"] = "";
      // Auth-Methode am Introspection-Endpoint: "basic" (default) oder "body"
      cfg["introspection_auth"] = "basic";
      // OIDC: falls true und id_token gewünscht, wird "openid" + nonce ergänzt (bei Implicit ggf. id_token angefordert)
      cfg["oidc_enabled"] = "true";
      cfg["http_get"] = "false";
      // Offline-Scope (für Refresh-Tokens) nur ergänzen, wenn explizit gewollt
      cfg["auto_add_offline_access"] = "false";
      // Nonce für OIDC
      cfg["nonce"] = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
      cfg["iframe_allowed"] = "false";
      cfg["retrieve_with_default_credentials"] = "false";

      // Optional: separate Client-Creds für Introspection (falls vom AS gefordert)
      // cfg["introspection_client_id"] = "";
      // cfg["introspection_client_secret"] = "";

      this.Configuration = cfg;
    }

    #region " Entry-URL generation "

    public string GenerateEntryUrlForOAuthCodeGrant(
        string clientId, string redirectUri,
        bool requestRefreshToken, bool requestIdToken,
        string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    ) {
      if (String.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      if (String.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      if (scopes == null || scopes.Length == 0) throw new ArgumentException("At least one scope is required.", nameof(scopes));

      var lst = new List<string>(scopes.Where(s => !String.IsNullOrWhiteSpace(s)));

      // Optional: offline_access nur ergänzen, wenn konfiguriert (OIDC-Welt)
      if (requestRefreshToken && IsTrue(this.GetConfig("auto_add_offline_access", "false")) && !lst.Contains("offline_access")) {
        lst.Add("offline_access");
      }
      // Optional: OIDC ID Token – nur wenn aktiviert
      if (requestIdToken && IsTrue(this.GetConfig("oidc_enabled", "true")) && !lst.Contains("openid")) {
        lst.Add("openid");
      }

      string scopeJoined = String.Join(" ", lst);

      var url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", string.Empty));
      url.Append("?response_type=code");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      if (additionalQueryParams != null) {
        string[] fobiddenAdditionalParams = { "response_type", "client_id", "redirect_uri", "scope", "state", "nonce" };
        foreach (var kvp in additionalQueryParams) {
          if (fobiddenAdditionalParams.Contains(kvp.Key)) {
            break;
          }
          string param = kvp.Value?.ToString();
          if (param == null) {
            param = string.Empty;
          }
          url.Append("&").Append(Uri.EscapeDataString(kvp.Key.ToString())).Append("=").Append(Uri.EscapeDataString(param));
        }
      }

      if (requestIdToken && IsTrue(this.GetConfig("oidc_enabled", "true"))) {
        if (this.Configuration.TryGetValue("nonce", out string nonce) && !String.IsNullOrWhiteSpace(nonce)) {
          url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
        }
      }

      return url.ToString();
    }

    [Obsolete("Implicit Grant is deprecated.")]
    public string GenerateEntryUrlForOAuthImplicitGrant(
      string clientId, string redirectUri,
      bool requestRefreshToken, bool requestIdToken,
      string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    ) {
      if (String.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      if (String.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      if (scopes == null || scopes.Length == 0) throw new ArgumentException("At least one scope is required.", nameof(scopes));

      string scopeJoined = String.Join(" ", scopes.Where(s => !String.IsNullOrWhiteSpace(s)));

      var url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", string.Empty));

      if (requestIdToken && IsTrue(this.GetConfig("oidc_enabled", "true"))) {
        url.Append("?response_type=id_token%20token");
      }
      else {
        url.Append("?response_type=token");
      }

      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      if (additionalQueryParams != null) {
        string[] fobiddenAdditionalParams = { "response_type", "client_id", "redirect_uri", "scope", "state", "nonce" };
        foreach (var kvp in additionalQueryParams) {
          if (fobiddenAdditionalParams.Contains(kvp.Key)) {
            break;
          }
          string param = kvp.Value?.ToString();
          if (param == null) {
            param = string.Empty;
          }
          url.Append("&").Append(Uri.EscapeDataString(kvp.Key.ToString())).Append("=").Append(Uri.EscapeDataString(param));
        }
      }

      if (requestIdToken && IsTrue(this.GetConfig("oidc_enabled", "true"))) {
        if (this.Configuration.TryGetValue("nonce", out string nonce) && !String.IsNullOrWhiteSpace(nonce)) {
          url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
        }
      }

      return url.ToString();
    }

    #endregion

    #region " Token retrival "

    public bool TryGetTokenFromRedirectedUrl(
      string finalUrlFromAuthFlow,
      string clientId, string clientSecret,
      out TokenIssuingResult result
    ) {
      result = new TokenIssuingResult();

      if (String.IsNullOrWhiteSpace(finalUrlFromAuthFlow)) {
        result.error = "invalid_argument";
        result.error_description = "finalUrlFromAuthFlow must not be empty.";
        return false;
      }

      if (!Uri.TryCreate(finalUrlFromAuthFlow, UriKind.Absolute, out Uri uri)) {
        result.error = "invalid_argument";
        result.error_description = "finalUrlFromAuthFlow is not a valid absolute URI.";
        return false;
      }

      // 1) Implicit-Flow: Token(s) im Fragment
      if (!String.IsNullOrEmpty(uri.Fragment)) {
        var fragmentValues = ParseFormStyle(uri.Fragment.TrimStart('#'));
        bool anyToken = false;

        if (fragmentValues.ContainsKey("access_token")) { result.access_token = fragmentValues["access_token"]; anyToken = true; }
        if (fragmentValues.ContainsKey("id_token")) { result.id_token = fragmentValues["id_token"]; anyToken = true; }
        if (fragmentValues.ContainsKey("token_type")) { result.token_type = fragmentValues["token_type"]; }
        if (fragmentValues.ContainsKey("expires_in") && Int32.TryParse(fragmentValues["expires_in"], NumberStyles.Integer, CultureInfo.InvariantCulture, out int seconds)) {
          result.expires_in = seconds;
        }
        if (fragmentValues.ContainsKey("scope")) { result.scope = fragmentValues["scope"]; }

        return anyToken;
      }

      // 2) Code-Flow
      var queryValues = ParseFormStyle(uri.Query.TrimStart('?'));
      if (queryValues.ContainsKey("error")) {
        result.error = queryValues["error"];
        result.error_description = queryValues.ContainsKey("error_description") ? queryValues["error_description"] : "Authorization server returned an error.";
        return false;
      }
      if (!queryValues.ContainsKey("code")) {
        result.error = "no_code_or_token";
        result.error_description = "Neither tokens in fragment nor authorization code in query found.";
        return false;
      }

      string redirectUriAgain = RemoveQueryAndFragment(uri);
      string code = queryValues["code"];

      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) {
        throw new InvalidOperationException("clientId and clientSecret are required to exchange the code for tokens.");
      }

      return this.ExchangeCodeForTokens(code, redirectUriAgain, clientId, clientSecret, out result);
    }

    public bool TryGetCodeFromRedirectedUrl(
      string finalUrlFromAuthFlow,
      out string code, out string finalUrlWithoutQuery
    ) {
      code = null; finalUrlWithoutQuery = null;
      if (String.IsNullOrWhiteSpace(finalUrlFromAuthFlow)) return false;
      if (!Uri.TryCreate(finalUrlFromAuthFlow, UriKind.Absolute, out Uri uri)) return false;

      var queryValues = ParseFormStyle(uri.Query.TrimStart('?'));
      if (queryValues.ContainsKey("code")) {
        code = queryValues["code"];
        finalUrlWithoutQuery = RemoveQueryAndFragment(uri);
        return true;
      }
      return false;
    }

    public bool TryGetAccessTokenViaOAuthCode(
      string code,
      string clientId, string clientSecret,
      string redirectUriAgain,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    ) {
      result = new TokenIssuingResult();

      if (String.IsNullOrWhiteSpace(code)) {
        result.error = "invalid_argument";
        result.error_description = "code must not be empty.";
        return false; 
      }
      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) {
        result.error = "missing_client_credentials";
        result.error_description = "clientId and clientSecret are required."; 
        return false; 
      }
      if (String.IsNullOrWhiteSpace(redirectUriAgain)) {
        result.error = "missing_redirect_uri"; 
        result.error_description = "redirectUriAgain must be provided and exactly match the authorization request."; 
        return false;
      }

      return this.ExchangeCodeForTokens(code, redirectUriAgain, clientId, clientSecret, out result);
    }

    public bool TryGetAccessTokenViaOAuthClientCredentials(
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    ) {
      result = new TokenIssuingResult();

      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) {
        result.error = "missing_client_credentials";
        result.error_description = "clientId and clientSecret are required.";
        return false;
      }

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["grant_type"] = "client_credentials"
      };

      // Optional: feste Scopes für Client-Credentials (z. B. aus Config)
      if (this.Configuration.TryGetValue("client_credentials_scope", out string ccScope) && !String.IsNullOrWhiteSpace(ccScope)) {
        form["scope"] = ccScope;
      }

      var req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", string.Empty));

      bool basicAuth = true; // Default
      if (this.TryGetConfigurationValue("client_credentials_via_basicauth", out string settingValue)) {
        basicAuth = IsTrue(settingValue);
      }

      if (this.ClientCredentialsViaBasicAuth) {
        ApplyBasicAuth(req, clientId, clientSecret); //Standard: Client-Auth via Basic (RFC 6749 §2.3.1)
      }
      else {
        form["client_id"] = clientId;
        form["client_secret"] = clientSecret;
      }
      req.Content = new FormUrlEncodedContent(form);

      return this.SendTokenRequest(req, out result);
    }

    public bool TryGetAccessTokenViaOAuthRefreshToken(
      string refreshToken,
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    ) {
      result = new TokenIssuingResult();

      if (String.IsNullOrWhiteSpace(refreshToken)) {
        result.error = "invalid_argument";
        result.error_description = "refreshToken must not be empty.";
        return false; 
      }
      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) { 
        result.error = "missing_client_credentials";
        result.error_description = "clientId and clientSecret are required.";
        return false; 
      }

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = refreshToken
      };

      var req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", string.Empty));
      req.Content = new FormUrlEncodedContent(form);

      if (this.ClientCredentialsViaBasicAuth) {
        ApplyBasicAuth(req, clientId, clientSecret); //Standard: Client-Auth via Basic (RFC 6749 §2.3.1)
      }
      else {
        form["client_id"] = clientId;
        form["client_secret"] = clientSecret;
      }

      return this.SendTokenRequest(req, out result);
    }

    #endregion

    #region " Token validation / introspection "

    public bool TryResolveSubjectAndScopes(
      string accessToken,
      out string subject,
      out string[] scopes,
      out Dictionary<string, object> additionalClaims
    ) {
      subject = null; scopes = null; additionalClaims = null;
      if (String.IsNullOrWhiteSpace(accessToken)) return false;

      TokenInfoResponse info;
      if (!this.TryCallTokenInfo(accessToken, out info)) {
        // Fallback: OIDC UserInfo falls vorhanden
        if (this.TryCallUserInfo(accessToken, out var ui)) {
          subject = ui.Sub;
          scopes = new string[0];
          additionalClaims = ui.ToDictionary();
          return !String.IsNullOrWhiteSpace(subject);
        }
        return false;
      }

      scopes = !String.IsNullOrWhiteSpace(info.Scope)
        ? info.Scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
        : new string[0];

      subject = !String.IsNullOrWhiteSpace(info.Sub) ? info.Sub : info.UserId;

      additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      if (!String.IsNullOrWhiteSpace(info.Aud)) additionalClaims["aud"] = info.Aud;
      if (info.ExpiresIn.HasValue) additionalClaims["expires_in"] = info.ExpiresIn.Value;
      if (!String.IsNullOrWhiteSpace(info.Scope)) additionalClaims["scope"] = info.Scope;

      return !String.IsNullOrWhiteSpace(subject);
    }

    public bool TryResolveSubjectAndScopes(
      string accessToken, string idToken,
      out string subject, out string[] scopes,
      out Dictionary<string, object> additionalClaims
     ) {
      subject = null; scopes = null; additionalClaims = null;
      if (String.IsNullOrWhiteSpace(accessToken) && String.IsNullOrWhiteSpace(idToken)) return false;

      // 1) Introspection versuchen
      TokenInfoResponse info = null;
      if (!String.IsNullOrWhiteSpace(accessToken)) {
        this.TryCallTokenInfo(accessToken, out info);
      }

      scopes = (info != null && !String.IsNullOrWhiteSpace(info.Scope))
        ? info.Scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
        : new string[0];

      // 2) ID-Token (non-validating) als Quelle für sub/Claims
      Dictionary<string, object> idClaims = null;
      if (!String.IsNullOrWhiteSpace(idToken)) {
        idClaims = TryDecodeJwtWithoutValidation(idToken);
        if (idClaims != null && idClaims.TryGetValue("sub", out object subObj) && subObj != null) {
          subject = Convert.ToString(subObj, CultureInfo.InvariantCulture);
        }
      }

      // 3) Falls noch kein subject: UserInfo (OIDC)
      if (String.IsNullOrWhiteSpace(subject) && !String.IsNullOrWhiteSpace(accessToken)) {
        if (this.TryCallUserInfo(accessToken, out var ui)) {
          subject = ui.Sub;
          additionalClaims = ui.ToDictionary();
        }
      }

      if (additionalClaims == null) additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      if (idClaims != null) foreach (var kv in idClaims) additionalClaims[kv.Key] = kv.Value;

      if (info != null) {
        if (!String.IsNullOrWhiteSpace(info.Aud)) additionalClaims["aud"] = info.Aud;
        if (info.ExpiresIn.HasValue) additionalClaims["expires_in"] = info.ExpiresIn.Value;
        if (!String.IsNullOrWhiteSpace(info.Scope)) additionalClaims["scope"] = info.Scope;
        if (String.IsNullOrWhiteSpace(subject) && !String.IsNullOrWhiteSpace(info.Sub)) subject = info.Sub;
        if (String.IsNullOrWhiteSpace(subject) && !String.IsNullOrWhiteSpace(info.UserId)) subject = info.UserId;
      }

      return !String.IsNullOrWhiteSpace(subject);
    }

    public bool TryValidateToken(
      string accessToken,
      out bool isActive,
      out DateTime? validUntil,
      out string invalidReason
    ) {
      isActive = false; validUntil = null; invalidReason = null;
      if (String.IsNullOrWhiteSpace(accessToken)) { invalidReason = "access_token is empty."; return false; }

      TokenInfoResponse info;
      if (!this.TryCallTokenInfo(accessToken, out info)) {
        invalidReason = "introspection_unavailable_or_failed";
        return false;
      }

      // Wenn das AS "inactive" liefert, betrachten wir es als gültige Auskunft.
      if (info.ExpiresIn.HasValue && info.ExpiresIn.Value > 0) {
        isActive = true;
        validUntil = DateTime.UtcNow.AddSeconds(info.ExpiresIn.Value);
        return true;
      }

      // Kein expires_in ableitbar → auf active Flag prüfen (über additional field in Introspection)
      // (Wir transportieren "active" intern im TokenInfoResponse über ExpiresIn==null & ggf. Zusatzclaims.)
      // Wenn ExpiresIn nicht ermittelbar war, aber der Introspection-Call erfolgreich war, interpretieren wir:
      // active=true → gültig ohne Ablaufzeit; active=false → ungültig.
      if (this._LastIntrospectionActive.HasValue) {
        isActive = this._LastIntrospectionActive.Value;
        if (!isActive) invalidReason = "inactive";
        return true;
      }

      // Fallback: keine verlässliche Info
      invalidReason = "unknown_activity";
      return false;
    }

    #endregion

    #region " Internal Helpers & private DTOs "

    private string GetConfig(string key, string fallback) {
      if (this.Configuration.TryGetValue(key, out string value) && !String.IsNullOrWhiteSpace(value)) return value;
      return fallback;
    }

    private static bool IsTrue(string s) {
      return !String.IsNullOrWhiteSpace(s) &&
             (s.Equals("true", StringComparison.OrdinalIgnoreCase) ||
              s.Equals("1", StringComparison.OrdinalIgnoreCase) ||
              s.Equals("yes", StringComparison.OrdinalIgnoreCase));
    }

    private static string RemoveQueryAndFragment(Uri uri) {
      var b = new StringBuilder();
      b.Append(uri.Scheme).Append("://").Append(uri.Host);
      if (!uri.IsDefaultPort) b.Append(":").Append(uri.Port.ToString(CultureInfo.InvariantCulture));
      b.Append(uri.AbsolutePath);
      return b.ToString();
    }

    private static Dictionary<string, string> ParseFormStyle(string input) {
      var dict = new Dictionary<string, string>(StringComparer.Ordinal);
      if (String.IsNullOrEmpty(input)) return dict;

      foreach (var kv in input.Split('&')) {
        if (String.IsNullOrEmpty(kv)) continue;
        int idx = kv.IndexOf('=');
        if (idx < 0) { var kOnly = UrlDecode(kv); if (!dict.ContainsKey(kOnly)) dict[kOnly] = String.Empty; continue; }
        string key = UrlDecode(kv.Substring(0, idx));
        string value = UrlDecode(kv.Substring(idx + 1));
        dict[key] = value;
      }
      return dict;
    }

    private static string UrlDecode(string s) {
      if (s == null) return null;
      string plusFixed = s.Replace("+", "%20");//, StringComparison.Ordinal);
      return Uri.UnescapeDataString(plusFixed);
    }

    private static void ApplyBasicAuth(HttpRequestMessage req, string clientId, string clientSecret) {
      string raw = $"{clientId}:{clientSecret}";
      string b64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(raw));
      req.Headers.Authorization = new AuthenticationHeaderValue("Basic", b64);
    }

    private bool ExchangeCodeForTokens(
        string code, string redirectUri,
        string clientId, string clientSecret,
        out TokenIssuingResult result) {
      result = new TokenIssuingResult();

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["grant_type"] = "authorization_code",
        ["code"] = code,
        ["redirect_uri"] = redirectUri
      };

      var req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", string.Empty));
      req.Content = new FormUrlEncodedContent(form);

      if (this.ClientCredentialsViaBasicAuth) {
        ApplyBasicAuth(req, clientId, clientSecret); //Standard: Client-Auth via Basic (RFC 6749 §2.3.1)
      }
      else {
        form["client_id"] = clientId;
        form["client_secret"] = clientSecret;
      }

      return this.SendTokenRequest(req, out result);
    }

    private bool SendTokenRequest(HttpRequestMessage request, out TokenIssuingResult result) {
      result = new TokenIssuingResult();

      HttpResponseMessage resp = null;
      string body = null;

      try {
        resp = this.HttpClient.SendAsync(request).GetAwaiter().GetResult();
        body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
      }
      catch (Exception ex) {
        result.error = "http_error";
        result.error_description = ex.Message;
        return false;
      }

      if (resp.StatusCode != HttpStatusCode.OK) {
        TokenErrorResponse err = null;
        try { err = JsonConvert.DeserializeObject<TokenErrorResponse>(body); } catch { /* ignore */ }

        result.error = err != null && !String.IsNullOrWhiteSpace(err.Error) ? err.Error : "token_endpoint_error";
        result.error_description = (err != null && !String.IsNullOrWhiteSpace(err.ErrorDescription))
          ? err.ErrorDescription
          : "Token endpoint returned " + ((int)resp.StatusCode).ToString(CultureInfo.InvariantCulture) + " " + resp.ReasonPhrase;

        return false;
      }

      TokenSuccessResponse data = null;
      try {
        data = JsonConvert.DeserializeObject<TokenSuccessResponse>(body);
      }
      catch (Exception ex) {
        result.error = "parse_error";
        result.error_description = "Failed to parse token response: " + ex.Message;
        return false;
      }

      if (data == null) { result.error = "empty_response"; result.error_description = "Token response was empty."; return false; }

      result.access_token = data.AccessToken;
      result.refresh_token = data.RefreshToken;
      result.id_token = data.IdToken;
      result.token_type = data.TokenType;
      if (data.ExpiresIn.HasValue) result.expires_in = data.ExpiresIn.Value;
      if (!String.IsNullOrWhiteSpace(data.Scope)) result.scope = data.Scope;

      return true;
    }

    // ---------- RFC 7662 Introspection ----------
    private bool TryCallTokenInfo(string accessToken, out TokenInfoResponse tokenInfo) {
      tokenInfo = null;

      // Erlaubt sowohl "introspection_endpoint" als auch (abwärtskompatibel) "tokeninfo_endpoint"
      string ep = this.GetConfig("introspection_endpoint", this.GetConfig("tokeninfo_endpoint", string.Empty));
      if (String.IsNullOrWhiteSpace(ep)) return false;

      // Optional abweichende Client-Creds für Introspection
      string clientId = null, clientSecret = null;
      if (!this.Configuration.TryGetValue("introspection_client_id", out clientId) || String.IsNullOrWhiteSpace(clientId)) {
        this.Configuration.TryGetValue("client_id", out clientId); // falls jemand das hier ablegt
      }
      if (!this.Configuration.TryGetValue("introspection_client_secret", out clientSecret) || String.IsNullOrWhiteSpace(clientSecret)) {
        this.Configuration.TryGetValue("client_secret", out clientSecret);
      }

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["token"] = accessToken,
        ["token_type_hint"] = "access_token"
      };

      var req = new HttpRequestMessage(HttpMethod.Post, ep) {
        Content = new FormUrlEncodedContent(form)
      };

      // Standard: Client-Auth via Basic; alternativ via Body (für AS, die es so verlangen)
      string authMode = this.GetConfig("introspection_auth", "basic");
      if (string.IsNullOrWhiteSpace(authMode)) {
        if (this.ClientCredentialsViaBasicAuth) {
          authMode = "basic";
        }
        else {
          authMode = "body";
        }

      }

      if (authMode == "basic") {
        ApplyBasicAuth(req, clientId, clientSecret); //Standard: Client-Auth via Basic (RFC 6749 §2.3.1)
      }
      else if (authMode == "body") {
        form["client_id"] = clientId;
        form["client_secret"] = clientSecret;
      }
      //else { //authMode == "none"
      //}

      req.Content = new FormUrlEncodedContent(form);

      try {

        var resp = this.HttpClient.SendAsync(req).GetAwaiter().GetResult();
        var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        if (resp.StatusCode != HttpStatusCode.OK) return false;

        var data = JsonConvert.DeserializeObject<IntrospectionResponse>(body);
        if (data == null) return false;

        // Merke active-Flag für TryValidateToken
        this._LastIntrospectionActive = data.Active;

        // expires_in aus exp ableiten (falls vorhanden)
        int? expiresIn = null;
        if (data.Exp.HasValue) {
          var dt = DateTimeOffset.FromUnixTimeSeconds(data.Exp.Value).UtcDateTime;
          var seconds = (int)Math.Round((dt - DateTime.UtcNow).TotalSeconds);
          expiresIn = seconds;
        }

        tokenInfo = new TokenInfoResponse {
          Aud = data.Aud,
          Scope = data.Scope,
          ExpiresIn = expiresIn,
          Sub = data.Sub,
          UserId = data.Sub
        };

        return true;
      }
      catch {
        return false;
      }
    }

    private bool TryCallUserInfo(string accessToken, out UserInfoResponse userinfo) {
      userinfo = null;

      string ep = this.GetConfig("userinfo_endpoint", string.Empty);
      if (String.IsNullOrWhiteSpace(ep)) return false;

      var req = new HttpRequestMessage(HttpMethod.Get, ep);
      req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      try {
        var resp = this.HttpClient.SendAsync(req).GetAwaiter().GetResult();
        var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (resp.StatusCode != HttpStatusCode.OK) return false;

        userinfo = JsonConvert.DeserializeObject<UserInfoResponse>(body) ?? new UserInfoResponse();
        return !String.IsNullOrWhiteSpace(userinfo.Sub);
      }
      catch {
        return false;
      }
    }

    private static Dictionary<string, object> TryDecodeJwtWithoutValidation(string jwt) {
      try {
        var parts = jwt.Split('.');
        if (parts.Length < 2) return null;
        var payload = parts[1];
        var payloadBytes = Base64UrlDecode(payload);
        var json = Encoding.UTF8.GetString(payloadBytes);

        var jObj = JObject.Parse(json);
        var dict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var p in jObj.Properties()) {
          dict[p.Name] = ConvertJToken(p.Value);
        }
        return dict;
      }
      catch { return null; }
    }

    private static object ConvertJToken(JToken token) {
      switch (token.Type) {
        case JTokenType.String:
          return token.ToString();
        case JTokenType.Integer:
          return token.ToObject<long>();
        case JTokenType.Float:
          return token.ToObject<double>();
        case JTokenType.Boolean:
          return token.ToObject<bool>();
        case JTokenType.Array:
          var list = new List<object>();
          foreach (var item in token.Children()) {
            list.Add(ConvertJToken(item));
          }
          return list.ToArray();
        case JTokenType.Object:
          var obj = new Dictionary<string, object>(StringComparer.Ordinal);
          foreach (var prop in ((JObject)token).Properties()) {
            obj[prop.Name] = ConvertJToken(prop.Value);
          }
          return obj;
        case JTokenType.Null:
          return null;
        default:
          return token.ToString();
      }
    }

    private static byte[] Base64UrlDecode(string base64Url) {
      string s = base64Url.Replace('-', '/').Replace('_', '+');
      switch (s.Length % 4) {
        case 2: s += "=="; break;
        case 3: s += "="; break;
        case 0: break;
        default: break;
      }
      return Convert.FromBase64String(s);
    }

    // ---------- State aus Introspection ----------
    private bool? _LastIntrospectionActive;

    // ---------- DTOs ----------
    private sealed class TokenSuccessResponse {
      [JsonProperty("access_token")]
      public string AccessToken { get; set; }

      [JsonProperty("expires_in")]
      public int? ExpiresIn { get; set; }

      [JsonProperty("refresh_token")]
      public string RefreshToken { get; set; }

      [JsonProperty("scope")]
      public string Scope { get; set; }

      [JsonProperty("token_type")]
      public string TokenType { get; set; }

      [JsonProperty("id_token")]
      public string IdToken { get; set; }
    }

    private sealed class TokenErrorResponse {
      [JsonProperty("error")]
      public string Error { get; set; }

      [JsonProperty("error_description")]
      public string ErrorDescription { get; set; }
    }

    // Generischer "TokenInfo" Container, befüllt aus RFC 7662 Introspection
    private sealed class TokenInfoResponse {
      [JsonProperty("aud")] public string Aud { get; set; }
      [JsonProperty("scope")] public string Scope { get; set; }
      [JsonProperty("expires_in")] public int? ExpiresIn { get; set; }
      [JsonProperty("sub")] public string Sub { get; set; }
      [JsonProperty("user_id")] public string UserId { get; set; }
    }

    // RFC 7662: typische Felder
    private sealed class IntrospectionResponse {
      [JsonProperty("active")] public bool? Active { get; set; }
      [JsonProperty("scope")] public string Scope { get; set; }
      [JsonProperty("client_id")] public string ClientId { get; set; }
      [JsonProperty("username")] public string Username { get; set; }
      [JsonProperty("token_type")] public string TokenType { get; set; }
      [JsonProperty("exp")] public long? Exp { get; set; }
      [JsonProperty("iat")] public long? Iat { get; set; }
      [JsonProperty("nbf")] public long? Nbf { get; set; }
      [JsonProperty("sub")] public string Sub { get; set; }
      [JsonProperty("aud")] public string Aud { get; set; }
      [JsonProperty("iss")] public string Iss { get; set; }
      [JsonProperty("jti")] public string Jti { get; set; }
    }

    // OIDC UserInfo (optional)
    private sealed class UserInfoResponse {
      [JsonProperty("sub")] public string Sub { get; set; }
      [JsonProperty("email")] public string Email { get; set; }
      [JsonProperty("email_verified")] public bool? EmailVerified { get; set; }
      [JsonProperty("name")] public string Name { get; set; }
      [JsonProperty("picture")] public string Picture { get; set; }
      [JsonProperty("given_name")] public string GivenName { get; set; }
      [JsonProperty("family_name")] public string FamilyName { get; set; }

      public Dictionary<string, object> ToDictionary() {
        var dict = new Dictionary<string, object>(StringComparer.Ordinal);
        if (!String.IsNullOrWhiteSpace(this.Sub)) dict["sub"] = this.Sub;
        if (!String.IsNullOrWhiteSpace(this.Email)) dict["email"] = this.Email;
        if (this.EmailVerified.HasValue) dict["email_verified"] = this.EmailVerified.Value;
        if (!String.IsNullOrWhiteSpace(this.Name)) dict["name"] = this.Name;
        if (!String.IsNullOrWhiteSpace(this.Picture)) dict["picture"] = this.Picture;
        if (!String.IsNullOrWhiteSpace(this.GivenName)) dict["given_name"] = this.GivenName;
        if (!String.IsNullOrWhiteSpace(this.FamilyName)) dict["family_name"] = this.FamilyName;
        return dict;
      }
    }

    #endregion

  }

}
