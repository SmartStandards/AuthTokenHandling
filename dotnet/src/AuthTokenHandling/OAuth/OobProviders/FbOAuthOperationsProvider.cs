using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;


#if NET5_0_OR_GREATER
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Security.AccessTokenHandling.OAuth.OobProviders {

  public class FacebookOAuthOperationsProvider : IOAuthOperationsProvider, IDisposable {

    private const string _DefaultGraphVersion = "v19.0";

    private const string _FbGraphBase = "https://graph.facebook.com";
    private const string _FbWebBase = "https://www.facebook.com";

    #region " Matadata & Config "

    private const string _FacebookIconUrl = "data:image/png;base64,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";

    private Dictionary<string, string> Configuration { get; } = new Dictionary<string, string>();

    public void SetConfigurationValue(string key, string value) {
      if (value == null) {
        value = string.Empty;
      }
      this.Configuration[key] = value;
    }
    public bool TryGetConfigurationValue(string key, out string value) {
      return this.Configuration.TryGetValue(key, out value);
    }

    public string ProviderInvariantName {
      get {
        return "facebook";
      }
    }

    public string ProviderDisplayTitle {
      get {
        return "Facebook";
      }
    }

    public string ProviderIconUrl {
      get {
        string configured;
        if (this.Configuration.TryGetValue("provider_icon_url", out configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return _FacebookIconUrl;
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
      return _SupportedCapabilities.Contains(capabilityName);
    }
    private static string[] _SupportedCapabilities = {
      "introspection", "id_token"
    };

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

    public void Dispose() {
      if (_HttpClient != null) {
        _HttpClient.Dispose();
      }
    }

    #endregion

    public FacebookOAuthOperationsProvider()
      : this(OAuthOperationsProviderCommonSetupHelper.DefaultHttpClientFactory) {
    }

    public FacebookOAuthOperationsProvider(Func<IOAuthOperationsProvider, HttpClient> httpClientFactory) {
      this.HttpClientFactory = httpClientFactory;

      // Standard-Config auf Facebook setzen (überschreibbar via Configuration[...]):
      var version = _DefaultGraphVersion;

      this.Configuration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      this.Configuration["graph_api_version"] = version;
      this.Configuration["authorization_endpoint"] = $"{_FbWebBase}/{version}/dialog/oauth";
      this.Configuration["token_endpoint"] = $"{_FbGraphBase}/{version}/oauth/access_token";
      this.Configuration["tokeninfo_endpoint"] = $"{_FbGraphBase}/{version}/debug_token";
      // Felder für /me: id,name,email,first_name,last_name,picture
      this.Configuration["userinfo_endpoint"] = $"{_FbGraphBase}/{version}/me?fields=id,name,email,first_name,last_name,picture";
      this.Configuration["nonce"] = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture); // wird bei FB nicht genutzt
      // Optional: app_access_token ODER (app_id + app_secret)
      // this.Configuration["app_access_token"] = "<app_id>|<app_secret>";
      // this.Configuration["app_id"] = "<app_id>";
      // this.Configuration["app_secret"] = "<app_secret>";
    }

    #region " Entry-URL generation "

    public string GenerateEntryUrlForOAuthCodeGrant(
        string clientId, string redirectUri,
        bool requestRefreshToken, bool requestIdToken,
        string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    ) {

      if (additionalQueryParams != null && additionalQueryParams.Any()) {
        SecLogger.LogWarning($"{this.GetType().Name} does not support additionalQueryParams and will ignore the passed ones!");
      }

      if (String.IsNullOrWhiteSpace(clientId)) {
        throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      }

      if (String.IsNullOrWhiteSpace(redirectUri)) {
        throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      }

      if (scopes == null || scopes.Length == 0) {
        throw new ArgumentException("At least one scope is required.", nameof(scopes));
      }

      // Facebook erwartet i. d. R. komma-separierte Berechtigungen.
      string scopeJoined = String.Join(",", scopes);

      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", $"{_FbWebBase}/{_DefaultGraphVersion}/dialog/oauth"));
      url.Append("?response_type=code");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      // Facebook: kein refresh_token Konzept; requestRefreshToken wird ignoriert.
      // Facebook unterstützt kein OIDC/id_token; requestIdToken wird ignoriert.

      return url.ToString();
    }

    [Obsolete("Implicit Grant is deprecated.")]
    public string GenerateEntryUrlForOAuthImplicitGrant(
      string clientId, string redirectUri,
      bool requestRefreshToken, bool requestIdToken,
      string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    ) {

      if (additionalQueryParams != null && additionalQueryParams.Any()) {
        SecLogger.LogWarning($"{this.GetType().Name} does not support additionalQueryParams and will ignore the passed ones!");
      }

      if (String.IsNullOrWhiteSpace(clientId)) {
        throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      }

      if (String.IsNullOrWhiteSpace(redirectUri)) {
        throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      }

      if (scopes == null || scopes.Length == 0) {
        throw new ArgumentException("At least one scope is required.", nameof(scopes));
      }

      string scopeJoined = String.Join(",", scopes);

      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", $"{_FbWebBase}/{_DefaultGraphVersion}/dialog/oauth"));

      // Facebook liefert im Implicit-Flow ein access_token (kein id_token).
      url.Append("?response_type=token");

      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      // requestRefreshToken / requestIdToken: bei Facebook nicht relevant.

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

      Uri uri;
      if (!Uri.TryCreate(finalUrlFromAuthFlow, UriKind.Absolute, out uri)) {
        result.error = "invalid_argument";
        result.error_description = "finalUrlFromAuthFlow is not a valid absolute URI.";
        return false;
      }

      // 1) Implicit-Flow: Tokens im Fragment (#access_token=...)
      if (!String.IsNullOrEmpty(uri.Fragment)) {
        Dictionary<string, string> fragmentValues = ParseFormStyle(uri.Fragment.TrimStart('#'));
        bool anyToken = false;

        if (fragmentValues.ContainsKey("access_token")) {
          result.access_token = fragmentValues["access_token"];
          anyToken = true;
        }

        if (fragmentValues.ContainsKey("token_type")) {
          result.token_type = fragmentValues["token_type"];
        }

        if (fragmentValues.ContainsKey("expires_in")) {
          int seconds;
          if (Int32.TryParse(fragmentValues["expires_in"], NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds)) {
            result.expires_in = seconds;
          }
        }

        if (fragmentValues.ContainsKey("scope")) {
          result.scope = fragmentValues["scope"];
        }

        // Facebook liefert kein id_token.
        return anyToken;
      }

      // 2) Code-Flow: ?code=... (oder ?error=...)
      Dictionary<string, string> queryValues = ParseFormStyle(uri.Query.TrimStart('?'));

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

      code = null;
      finalUrlWithoutQuery = null;

      if (String.IsNullOrWhiteSpace(finalUrlFromAuthFlow)) {
        return false;
      }

      Uri uri;
      if (!Uri.TryCreate(finalUrlFromAuthFlow, UriKind.Absolute, out uri)) {
        return false;
      }

      Dictionary<string, string> queryValues = ParseFormStyle(uri.Query.TrimStart('?'));

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

      // Hinweis: Facebook unterstützt client_credentials für App-Access-Tokens,
      // die aber NICHT für Endnutzer-Daten gedacht sind. Wir spiegeln das Verhalten
      // des bisherigen Google-Codes und markieren es als nicht unterstützt.
      result = new TokenIssuingResult {
        error = "unsupported_grant_type",
        error_description = "Facebook client_credentials is for app tokens only, not for end-user data."
      };

      return false;
    }

    public bool TryGetAccessTokenViaOAuthRefreshToken(
      string refreshToken,
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    ) {

      // Facebook gibt keine Refresh Tokens aus. Long-lived Tokens werden separat über
      // fb_exchange_token erreicht – ist hier nicht abgebildet.
      result = new TokenIssuingResult {
        error = "unsupported_grant_type",
        error_description = "Facebook does not issue refresh tokens. Use long-lived token exchange separately if needed."
      };
      return false;
    }

    #endregion

    #region " Token validation / introspection "

    public bool TryResolveSubjectAndScopes(
      string accessToken,
      out string subject,
      out string[] scopes,
      out Dictionary<string, object> additionalClaims
    ) {

      subject = null;
      scopes = null;
      additionalClaims = null;

      if (String.IsNullOrWhiteSpace(accessToken)) {
        return false;
      }

      TokenInfoResponse tokenInfo;
      if (!this.TryCallTokenInfo(accessToken, out tokenInfo)) {
        // Fallback: Versuche /me für die subject (ohne Scopes)
        UserInfoResponse fbUser;
        if (this.TryCallUserInfo(accessToken, out fbUser)) {
          subject = fbUser.Sub;
          additionalClaims = fbUser.ToDictionary();
          scopes = new string[0];
          return !String.IsNullOrWhiteSpace(subject);
        }
        return false;
      }

      if (!String.IsNullOrWhiteSpace(tokenInfo.Scope)) {
        scopes = tokenInfo.Scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
      }
      else {
        scopes = new string[0];
      }

      if (!String.IsNullOrWhiteSpace(tokenInfo.Sub)) {
        subject = tokenInfo.Sub;
      }
      else if (!String.IsNullOrWhiteSpace(tokenInfo.UserId)) {
        subject = tokenInfo.UserId;
      }
      else {
        UserInfoResponse userinfo;
        if (this.TryCallUserInfo(accessToken, out userinfo)) {
          subject = userinfo.Sub;
          additionalClaims = userinfo.ToDictionary();
        }
      }

      if (additionalClaims == null) {
        additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      }

      additionalClaims["aud"] = tokenInfo.Aud;
      if (tokenInfo.ExpiresIn.HasValue) {
        additionalClaims["expires_in"] = tokenInfo.ExpiresIn.Value;
      }

      if (!String.IsNullOrWhiteSpace(tokenInfo.Scope)) {
        additionalClaims["scope"] = tokenInfo.Scope;
      }

      return !String.IsNullOrWhiteSpace(subject);
    }

    public bool TryResolveSubjectAndScopes(
      string accessToken, string idToken,
      out string subject, out string[] scopes,
      out Dictionary<string, object> additionalClaims
     ) {

      // Facebook liefert kein id_token – wir ignorieren es.
      subject = null;
      scopes = null;
      additionalClaims = null;

      if (String.IsNullOrWhiteSpace(accessToken) && String.IsNullOrWhiteSpace(idToken)) {
        return false;
      }

      TokenInfoResponse tokenInfo = null;
      if (!String.IsNullOrWhiteSpace(accessToken)) {
        this.TryCallTokenInfo(accessToken, out tokenInfo);
      }

      if (tokenInfo != null && !String.IsNullOrWhiteSpace(tokenInfo.Scope)) {
        scopes = tokenInfo.Scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
      }
      else {
        scopes = new string[0];
      }

      // subject aus Tokeninfo oder via /me
      if (tokenInfo != null) {
        if (!String.IsNullOrWhiteSpace(tokenInfo.Sub)) {
          subject = tokenInfo.Sub;
        }
        else if (!String.IsNullOrWhiteSpace(tokenInfo.UserId)) {
          subject = tokenInfo.UserId;
        }
      }

      if (String.IsNullOrWhiteSpace(subject) && !String.IsNullOrWhiteSpace(accessToken)) {
        UserInfoResponse userinfo;
        if (this.TryCallUserInfo(accessToken, out userinfo)) {
          subject = userinfo.Sub;
          if (additionalClaims == null) {
            additionalClaims = userinfo.ToDictionary();
          }
        }
      }

      if (additionalClaims == null) {
        additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      }

      if (tokenInfo != null) {
        additionalClaims["aud"] = tokenInfo.Aud;
        if (tokenInfo.ExpiresIn.HasValue) {
          additionalClaims["expires_in"] = tokenInfo.ExpiresIn.Value;
        }
        if (!String.IsNullOrWhiteSpace(tokenInfo.Scope)) {
          additionalClaims["scope"] = tokenInfo.Scope;
        }
      }

      return !String.IsNullOrWhiteSpace(subject);
    }

    public bool TryValidateToken(
      string accessToken,
      out bool isActive,
      out DateTime? validUntil,
      out string invalidReason
    ) {

      isActive = false;
      validUntil = null;
      invalidReason = null;

      if (String.IsNullOrWhiteSpace(accessToken)) {
        invalidReason = "access_token is empty.";
        return false;
      }

      TokenInfoResponse tokenInfo;
      if (!this.TryCallTokenInfo(accessToken, out tokenInfo)) {
        invalidReason = "debug_token not reachable or app_access_token missing.";
        return false;
      }

      if (tokenInfo.ExpiresIn.HasValue && tokenInfo.ExpiresIn.Value > 0) {
        isActive = true;
        validUntil = DateTime.UtcNow.AddSeconds(tokenInfo.ExpiresIn.Value);
        return true;
      }

      isActive = false;
      invalidReason = "expired_or_invalid";
      return true;
    }

    #endregion

    #region " Internal Helpers & private DTOs "

    private string GetConfig(string key, string fallback) {
      string value;
      if (this.Configuration.TryGetValue(key, out value) && !String.IsNullOrWhiteSpace(value)) {
        return value;
      }
      return fallback;
    }

    private static string RemoveQueryAndFragment(Uri uri) {
      StringBuilder b = new StringBuilder();
      b.Append(uri.Scheme);
      b.Append("://");
      b.Append(uri.Host);
      if (!uri.IsDefaultPort) {
        b.Append(":").Append(uri.Port.ToString(CultureInfo.InvariantCulture));
      }
      b.Append(uri.AbsolutePath);
      return b.ToString();
    }

    private static Dictionary<string, string> ParseFormStyle(string input) {
      Dictionary<string, string> dict = new Dictionary<string, string>(StringComparer.Ordinal);
      if (String.IsNullOrEmpty(input)) {
        return dict;
      }

      string[] pairs = input.Split('&');
      for (int i = 0; i < pairs.Length; i++) {
        string kv = pairs[i];
        if (String.IsNullOrEmpty(kv)) {
          continue;
        }

        int idx = kv.IndexOf('=');
        if (idx < 0) {
          string kOnly = UrlDecode(kv);
          if (!dict.ContainsKey(kOnly)) {
            dict[kOnly] = String.Empty;
          }
          continue;
        }

        string key = UrlDecode(kv.Substring(0, idx));
        string value = UrlDecode(kv.Substring(idx + 1));
        dict[key] = value;
      }

      return dict;
    }

    private static string UrlDecode(string s) {
      if (s == null) {
        return null;
      }

      string plusFixed = s.Replace("+", "%20", StringComparison.Ordinal);
      return Uri.UnescapeDataString(plusFixed);
    }

    private bool ExchangeCodeForTokens(
        string code, string redirectUri,
        string clientId, string clientSecret,
        out TokenIssuingResult result) {
      result = new TokenIssuingResult();

      // Facebook erwartet: client_id, redirect_uri, client_secret, code
      // (grant_type ist nicht erforderlich und wird hier bewusst NICHT gesendet)
      Dictionary<string, string> form = new Dictionary<string, string>(StringComparer.Ordinal);
      form["code"] = code;
      form["redirect_uri"] = redirectUri;
      form["client_id"] = clientId;
      form["client_secret"] = clientSecret;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", $"{_FbGraphBase}/{_DefaultGraphVersion}/oauth/access_token"));
      req.Content = new FormUrlEncodedContent(form);

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
        try {
          err = JsonSerializer.Deserialize<TokenErrorResponse>(body);
        }
        catch {
          // Ignorieren – generische Meldung
        }

        result.error = err != null && !String.IsNullOrWhiteSpace(err.Error) ? err.Error : "token_endpoint_error";
        if (err != null && !String.IsNullOrWhiteSpace(err.ErrorDescription)) {
          result.error_description = err.ErrorDescription;
        }
        else {
          result.error_description = "Token endpoint returned " + ((int)resp.StatusCode).ToString(CultureInfo.InvariantCulture) + " " + resp.ReasonPhrase;
        }

        return false;
      }

      TokenSuccessResponse data = null;
      try {
        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;
        data = JsonSerializer.Deserialize<TokenSuccessResponse>(body, options);
      }
      catch (Exception ex) {
        result.error = "parse_error";
        result.error_description = "Failed to parse token response: " + ex.Message;
        return false;
      }

      if (data == null) {
        result.error = "empty_response";
        result.error_description = "Token response was empty.";
        return false;
      }

      result.access_token = data.AccessToken;
      // Facebook liefert kein refresh_token:
      result.refresh_token = null;
      result.id_token = null; // kein id_token bei Facebook
      result.token_type = data.TokenType;
      if (data.ExpiresIn.HasValue) {
        result.expires_in = data.ExpiresIn.Value;
      }

      if (!String.IsNullOrWhiteSpace(data.Scope)) {
        result.scope = data.Scope;
      }

      return true;
    }

    private bool TryCallTokenInfo(string accessToken, out TokenInfoResponse tokenInfo) {
      tokenInfo = null;

      // Facebooks debug_token benötigt ein App-Access-Token
      string appAccess;
      if (!this.Configuration.TryGetValue("app_access_token", out appAccess) || String.IsNullOrWhiteSpace(appAccess)) {
        string appId, appSecret;
        if (this.Configuration.TryGetValue("app_id", out appId) && !String.IsNullOrWhiteSpace(appId) &&
            this.Configuration.TryGetValue("app_secret", out appSecret) && !String.IsNullOrWhiteSpace(appSecret)) {
          appAccess = appId + "|" + appSecret;
        }
      }

      if (String.IsNullOrWhiteSpace(appAccess)) {
        return false; // Ohne App-Access-Token können wir nicht introspektieren
      }

      string endpoint = this.GetConfig("tokeninfo_endpoint", $"{_FbGraphBase}/{_DefaultGraphVersion}/debug_token");
      string url = endpoint + "?input_token=" + Uri.EscapeDataString(accessToken) + "&access_token=" + Uri.EscapeDataString(appAccess);

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, url);

      try {
        HttpResponseMessage resp = this.HttpClient.SendAsync(req).GetAwaiter().GetResult();
        string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        if (resp.StatusCode != HttpStatusCode.OK) {
          return false;
        }

        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;

        var envelope = JsonSerializer.Deserialize<FacebookDebugTokenEnvelope>(body, options);
        if (envelope == null || envelope.Data == null) {
          return false;
        }

        var d = envelope.Data;

        int? expiresIn = null;
        if (d.ExpiresAt.HasValue) {
          try {
            var dt = DateTimeOffset.FromUnixTimeSeconds(d.ExpiresAt.Value).UtcDateTime;
            var seconds = (int)(dt - DateTime.UtcNow).TotalSeconds;
            expiresIn = seconds;
          }
          catch { }
        }

        tokenInfo = new TokenInfoResponse {
          Aud = d.AppId,
          Scope = (d.Scopes != null && d.Scopes.Length > 0) ? String.Join(" ", d.Scopes) : null,
          ExpiresIn = expiresIn,
          Sub = null, // Facebook liefert sub nicht im debug_token
          UserId = d.UserId
        };
        return true;
      }
      catch {
        return false;
      }
    }

    private bool TryCallUserInfo(string accessToken, out UserInfoResponse userinfo) {
      userinfo = null;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, this.GetConfig("userinfo_endpoint", $"{_FbGraphBase}/{_DefaultGraphVersion}/me?fields=id,name,email,first_name,last_name,picture"));
      req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      try {
        HttpResponseMessage resp = this.HttpClient.SendAsync(req).GetAwaiter().GetResult();
        string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        if (resp.StatusCode != HttpStatusCode.OK) {
          return false;
        }

        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;

        userinfo = JsonSerializer.Deserialize<UserInfoResponse>(body, options) ?? new UserInfoResponse();

        // Mapping Facebook -> unsere erwarteten Felder
        if (userinfo != null) {
          if (String.IsNullOrWhiteSpace(userinfo.Sub) && !String.IsNullOrWhiteSpace(userinfo.Id)) {
            userinfo.Sub = userinfo.Id;
          }
          if (String.IsNullOrWhiteSpace(userinfo.GivenName) && !String.IsNullOrWhiteSpace(userinfo.FirstName)) {
            userinfo.GivenName = userinfo.FirstName;
          }
          if (String.IsNullOrWhiteSpace(userinfo.FamilyName) && !String.IsNullOrWhiteSpace(userinfo.LastName)) {
            userinfo.FamilyName = userinfo.LastName;
          }
          if (String.IsNullOrWhiteSpace(userinfo.Picture)) {
            string url = userinfo.PictureContainer != null && userinfo.PictureContainer.Data != null ? userinfo.PictureContainer.Data.Url : null;
            if (!String.IsNullOrWhiteSpace(url)) {
              userinfo.Picture = url;
            }
          }
        }

        return userinfo != null && !String.IsNullOrWhiteSpace(userinfo.Sub);
      }
      catch {
        return false;
      }
    }

    private static Dictionary<string, object> TryDecodeJwtWithoutValidation(string jwt) {
      // Facebook stellt kein id_token bereit; Methode beibehalten (kein Einsatzfall)
      try {
        string[] parts = jwt.Split('.');
        if (parts.Length < 2) {
          return null;
        }

        string payload = parts[1];
        byte[] payloadBytes = Base64UrlDecode(payload);
        string json = Encoding.UTF8.GetString(payloadBytes);

        JsonDocument doc = JsonDocument.Parse(json);
        Dictionary<string, object> dict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (JsonProperty p in doc.RootElement.EnumerateObject()) {
          dict[p.Name] = JsonElementToDotNet(p.Value);
        }

        return dict;
      }
      catch {
        return null;
      }
    }

    private static object JsonElementToDotNet(JsonElement el) {
      switch (el.ValueKind) {
        case JsonValueKind.String:
          return el.GetString();
        case JsonValueKind.Number:
          long l;
          if (el.TryGetInt64(out l)) {
            return l;
          }
          double d;
          if (el.TryGetDouble(out d)) {
            return d;
          }
          return el.GetRawText();
        case JsonValueKind.True:
          return true;
        case JsonValueKind.False:
          return false;
        case JsonValueKind.Array: {
            List<object> list = new List<object>();
            foreach (JsonElement item in el.EnumerateArray()) {
              list.Add(JsonElementToDotNet(item));
            }
            return list.ToArray();
          }
        case JsonValueKind.Object: {
            Dictionary<string, object> obj = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (JsonProperty p in el.EnumerateObject()) {
              obj[p.Name] = JsonElementToDotNet(p.Value);
            }
            return obj;
          }
        default:
          return null;
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

    private sealed class TokenSuccessResponse {
      [JsonPropertyName("access_token")]
      public string AccessToken { get; set; }

      [JsonPropertyName("expires_in")]
      public int? ExpiresIn { get; set; }

      // Facebook liefert keinen Refresh-Token
      [JsonPropertyName("refresh_token")]
      public string RefreshToken { get; set; }

      [JsonPropertyName("scope")]
      public string Scope { get; set; }

      [JsonPropertyName("token_type")]
      public string TokenType { get; set; }

      // Facebook liefert kein id_token
      [JsonPropertyName("id_token")]
      public string IdToken { get; set; }
    }

    private sealed class TokenErrorResponse {
      [JsonPropertyName("error")]
      public string Error { get; set; }

      [JsonPropertyName("error_description")]
      public string ErrorDescription { get; set; }
    }

    // Wird durch TryCallTokenInfo mit den Werten aus debug_token befüllt (gemappt).
    private sealed class TokenInfoResponse {
      [JsonPropertyName("aud")]
      public string Aud { get; set; }

      [JsonPropertyName("scope")]
      public string Scope { get; set; }

      [JsonPropertyName("expires_in")]
      public int? ExpiresIn { get; set; }

      [JsonPropertyName("sub")]
      public string Sub { get; set; }

      [JsonPropertyName("user_id")]
      public string UserId { get; set; }
    }

    public sealed class PictureContainer {
      [JsonPropertyName("data")]
      public PictureData Data { get; set; }
    }

    public sealed class PictureData {
      [JsonPropertyName("url")]
      public string Url { get; set; }
    }

    // Facebook /me Mapping
    private sealed class UserInfoResponse {
      // Google-kompatibel:
      [JsonPropertyName("sub")]
      public string Sub { get; set; }

      [JsonPropertyName("email")]
      public string Email { get; set; }

      [JsonPropertyName("email_verified")]
      public bool? EmailVerified { get; set; }

      [JsonPropertyName("name")]
      public string Name { get; set; }

      [JsonPropertyName("picture")]
      public string Picture { get; set; }

      [JsonPropertyName("given_name")]
      public string GivenName { get; set; }

      [JsonPropertyName("family_name")]
      public string FamilyName { get; set; }

      // Facebook-spezifisch (für Mapping):
      [JsonPropertyName("id")]
      public string Id { get; set; }

      [JsonPropertyName("first_name")]
      public string FirstName { get; set; }

      [JsonPropertyName("last_name")]
      public string LastName { get; set; }

      [JsonPropertyName("picture")]
      public PictureContainer PictureContainer { get; set; }

      public Dictionary<string, object> ToDictionary() {
        // sicherstellen, dass Mapping vollzogen ist
        if (String.IsNullOrWhiteSpace(this.Sub) && !String.IsNullOrWhiteSpace(this.Id)) this.Sub = this.Id;
        if (String.IsNullOrWhiteSpace(this.GivenName) && !String.IsNullOrWhiteSpace(this.FirstName)) this.GivenName = this.FirstName;
        if (String.IsNullOrWhiteSpace(this.FamilyName) && !String.IsNullOrWhiteSpace(this.LastName)) this.FamilyName = this.LastName;
        if (String.IsNullOrWhiteSpace(this.Picture) && this.PictureContainer != null && this.PictureContainer.Data != null && !String.IsNullOrWhiteSpace(this.PictureContainer.Data.Url)) {
          this.Picture = this.PictureContainer.Data.Url;
        }

        Dictionary<string, object> dict = new Dictionary<string, object>(StringComparer.Ordinal);
        if (!String.IsNullOrWhiteSpace(this.Sub)) { dict["sub"] = this.Sub; }
        if (!String.IsNullOrWhiteSpace(this.Email)) { dict["email"] = this.Email; }
        if (this.EmailVerified.HasValue) { dict["email_verified"] = this.EmailVerified.Value; }
        if (!String.IsNullOrWhiteSpace(this.Name)) { dict["name"] = this.Name; }
        if (!String.IsNullOrWhiteSpace(this.Picture)) { dict["picture"] = this.Picture; }
        if (!String.IsNullOrWhiteSpace(this.GivenName)) { dict["given_name"] = this.GivenName; }
        if (!String.IsNullOrWhiteSpace(this.FamilyName)) { dict["family_name"] = this.FamilyName; }
        return dict;
      }
    }

    // Facebook debug_token Envelope
    private sealed class FacebookDebugTokenEnvelope {
      [JsonPropertyName("data")]
      public FacebookDebugTokenData Data { get; set; }
    }

    private sealed class FacebookDebugTokenData {
      [JsonPropertyName("app_id")]
      public string AppId { get; set; }

      [JsonPropertyName("type")]
      public string Type { get; set; }

      [JsonPropertyName("application")]
      public string Application { get; set; }

      [JsonPropertyName("data_access_expires_at")]
      public long? DataAccessExpiresAt { get; set; }

      [JsonPropertyName("expires_at")]
      public long? ExpiresAt { get; set; }

      [JsonPropertyName("is_valid")]
      public bool? IsValid { get; set; }

      [JsonPropertyName("issued_at")]
      public long? IssuedAt { get; set; }

      [JsonPropertyName("scopes")]
      public string[] Scopes { get; set; }

      [JsonPropertyName("user_id")]
      public string UserId { get; set; }
    }

    #endregion

  }

}

#endif
