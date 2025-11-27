using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
#if NET5_0_OR_GREATER
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Security.AccessTokenHandling.OAuth.OobProviders {

  public class MicrosoftOAuthOperationsProvider : IOAuthOperationsProvider, IDisposable {

    // Defaults für Microsoft Identity Platform v2 (MSA/Live via tenant=consumers)
    private const string _MsLoginBase = "https://login.microsoftonline.com";
    private const string _MsTenantDefault = "consumers"; // nur Privatkonten („Microsoft Live“)

    private const string _AuthorizePath = "oauth2/v2.0/authorize";
    private const string _TokenPath = "oauth2/v2.0/token";

    // OIDC UserInfo läuft über Microsoft Graph
    private const string _MsGraphUserInfo = "https://graph.microsoft.com/oidc/userinfo";
    private const string _MsGraphMe = "https://graph.microsoft.com/v1.0/me";

    #region " Matadata & Config "

    private const string _MsIconUrl = "data:image/png;base64,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";

    private Dictionary<string, string> Configuration { get; } = new Dictionary<string, string>();

    public void SetConfigurationValue(string key, string value) {
      if (value == null) {
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
      get { return "microsoft"; }
    }

    public string ProviderDisplayTitle {
      get { return "Microsoft"; }
    }

    public string ProviderIconUrl {
      get {
        if (this.Configuration.TryGetValue("provider_icon_url", out string configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return _MsIconUrl;
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
      "introspection", "refresh_token" , "id_token"
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

    private static string[] _ClientInvalidatingSettingNames = {
      "retrieve_with_default_credentials"
    };

    public void Dispose() {
      if (_HttpClient != null) {
        _HttpClient.Dispose();
      }
    }

    #endregion
    
    public MicrosoftOAuthOperationsProvider()
      : this(OAuthOperationsProviderCommonSetupHelper.DefaultHttpClientFactory) {
    }

    public MicrosoftOAuthOperationsProvider(Func<IOAuthOperationsProvider, HttpClient> httpClientFactory) {
      this.HttpClientFactory = httpClientFactory;

      var cfg = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      cfg["tenant"] = _MsTenantDefault;

      // Endpunkte aus tenant aufbauen
      string tenant = cfg["tenant"];
      cfg["authorization_endpoint"] = $"{_MsLoginBase}/{tenant}/{_AuthorizePath}";
      cfg["token_endpoint"] = $"{_MsLoginBase}/{tenant}/{_TokenPath}";
      cfg["tokeninfo_endpoint"] = ""; // nicht vorhanden
      cfg["userinfo_endpoint"] = _MsGraphUserInfo;
      cfg["nonce"] = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

      this.Configuration = cfg; // ersetzt das read-only-Property-Backing aus dem Original
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

      if (String.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      if (String.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));

      var lst = new List<string>();
      if (scopes != null) lst.AddRange(scopes.Where(s => !String.IsNullOrWhiteSpace(s)));

      // Für Refresh-Token: offline_access anfordern
      if (requestRefreshToken && !lst.Any(s => String.Equals(s, "offline_access", StringComparison.Ordinal))) {
        lst.Add("offline_access"); // nötig, sonst kein Refresh Token
      }

      // Für ID Token (OIDC): openid & nonce
      if (requestIdToken && !lst.Any(s => String.Equals(s, "openid", StringComparison.Ordinal))) {
        lst.Add("openid");
      }

      if (lst.Count == 0) throw new ArgumentException("At least one scope is required.", nameof(scopes));

      string scopeJoined = String.Join(" ", lst);

      var url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", $"{_MsLoginBase}/{_MsTenantDefault}/{_AuthorizePath}"));
      url.Append("?response_type=code");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      if (requestIdToken) {
        if (this.Configuration.TryGetValue("nonce", out string nonce) && !String.IsNullOrWhiteSpace(nonce)) {
          url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
        }
      }

      // response_mode default = query → passt zu unserem Code-Parser

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

      if (String.IsNullOrWhiteSpace(clientId)) throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      if (String.IsNullOrWhiteSpace(redirectUri)) throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      if (scopes == null || scopes.Length == 0) throw new ArgumentException("At least one scope is required.", nameof(scopes));

      var lst = new List<string>(scopes);
      if (requestIdToken && !lst.Contains("openid")) lst.Add("openid");
      string scopeJoined = String.Join(" ", lst);

      var url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", $"{_MsLoginBase}/{_MsTenantDefault}/{_AuthorizePath}"));
      if (requestIdToken) {
        url.Append("?response_type=id_token%20token");
      }
      else {
        url.Append("?response_type=token");
      }
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));
      if (!String.IsNullOrEmpty(state)) url.Append("&state=").Append(Uri.EscapeDataString(state));

      if (requestIdToken && this.Configuration.TryGetValue("nonce", out string nonce) && !String.IsNullOrWhiteSpace(nonce)) {
        url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
      }

      // Microsoft empfiehlt Code+PKCE; Implicit ist nur aus Kompatibilitätsgründen hier.
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
      if (String.IsNullOrWhiteSpace(finalUrlFromAuthFlow)) { result.error = "invalid_argument"; result.error_description = "finalUrlFromAuthFlow must not be empty."; return false; }

      if (!Uri.TryCreate(finalUrlFromAuthFlow, UriKind.Absolute, out Uri uri)) {
        result.error = "invalid_argument"; result.error_description = "finalUrlFromAuthFlow is not a valid absolute URI."; return false;
      }

      // 1) Implicit-Flow: Tokens im Fragment
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
        result.error = "no_code_or_token"; result.error_description = "Neither tokens in fragment nor authorization code in query found."; return false;
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

      if (String.IsNullOrWhiteSpace(code)) { result.error = "invalid_argument"; result.error_description = "code must not be empty."; return false; }
      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) { result.error = "missing_client_credentials"; result.error_description = "clientId and clientSecret are required."; return false; }
      if (String.IsNullOrWhiteSpace(redirectUriAgain)) { result.error = "missing_redirect_uri"; result.error_description = "redirectUriAgain must be provided and exactly match the authorization request."; return false; }

      return this.ExchangeCodeForTokens(code, redirectUriAgain, clientId, clientSecret, out result);
    }

    public bool TryGetAccessTokenViaOAuthClientCredentials(
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    ) {
      // Nicht für Endnutzer-Daten; bleibt wie bei Google/Facebook/GitHub
      result = new TokenIssuingResult {
        error = "unsupported_grant_type",
        error_description = "Microsoft client_credentials is not for end-user data in this provider."
      };
      return false;
    }

    public bool TryGetAccessTokenViaOAuthRefreshToken(
      string refreshToken,
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    ) {
      result = new TokenIssuingResult();

      if (String.IsNullOrWhiteSpace(refreshToken)) { result.error = "invalid_argument"; result.error_description = "refreshToken must not be empty."; return false; }
      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) { result.error = "missing_client_credentials"; result.error_description = "clientId and clientSecret are required."; return false; }

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = refreshToken,
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret
        // Optional könnte man "scope" erneut senden; nicht zwingend.
      };

      var req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", $"{_MsLoginBase}/{_MsTenantDefault}/{_TokenPath}"));
      req.Content = new FormUrlEncodedContent(form);

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

      // 1) Versuche JWT zu dekodieren
      if (TryDecodeJwtWithoutValidation(accessToken) is Dictionary<string, object> jwt) {
        scopes = ExtractScopes(jwt);
        subject = ExtractSubject(jwt);
        additionalClaims = BuildAdditionalFromJwt(jwt);
      }
      else {
        scopes = new string[0];
      }

      // 2) Falls subject leer: versuche UserInfo (/oidc/userinfo), dann /v1.0/me
      if (String.IsNullOrWhiteSpace(subject)) {
        if (this.TryCallUserInfo(accessToken, out var ui)) {
          subject = ui.Sub;
          Merge(ref additionalClaims, ui.ToDictionary());
        }
      }

      return !String.IsNullOrWhiteSpace(subject);
    }

    public bool TryResolveSubjectAndScopes(
      string accessToken, string idToken,
      out string subject, out string[] scopes,
      out Dictionary<string, object> additionalClaims
     ) {
      subject = null; scopes = null; additionalClaims = null;

      Dictionary<string, object> idClaims = null;
      if (!String.IsNullOrWhiteSpace(idToken)) {
        idClaims = TryDecodeJwtWithoutValidation(idToken);
        if (idClaims != null && idClaims.TryGetValue("sub", out object subObj) && subObj != null) {
          subject = Convert.ToString(subObj, CultureInfo.InvariantCulture);
        }
      }

      if (!String.IsNullOrWhiteSpace(accessToken)) {
        if (TryDecodeJwtWithoutValidation(accessToken) is Dictionary<string, object> at) {
          scopes = ExtractScopes(at);
          if (String.IsNullOrWhiteSpace(subject)) subject = ExtractSubject(at);
          additionalClaims = BuildAdditionalFromJwt(at);
        }
      }

      if (additionalClaims == null) additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      if (idClaims != null) foreach (var kv in idClaims) additionalClaims[kv.Key] = kv.Value;

      // Fallback: UserInfo falls immer noch kein subject
      if (String.IsNullOrWhiteSpace(subject) && this.TryCallUserInfo(accessToken, out var ui)) {
        subject = ui.Sub;
        Merge(ref additionalClaims, ui.ToDictionary());
      }

      if (scopes == null) scopes = new string[0];
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

      if (TryDecodeJwtWithoutValidation(accessToken) is Dictionary<string, object> jwt) {
        if (jwt.TryGetValue("exp", out var expObj) && expObj != null && Int64.TryParse(Convert.ToString(expObj, CultureInfo.InvariantCulture), NumberStyles.Integer, CultureInfo.InvariantCulture, out long expUnix)) {
          var dt = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
          if (dt > DateTime.UtcNow) { isActive = true; validUntil = dt; return true; }
          isActive = false; invalidReason = "expired_or_invalid"; return true;
        }
      }

      // Fallback: Wenn UserInfo erreichbar → aktiv (ohne Auskunft über Ablauf)
      if (this.TryCallUserInfo(accessToken, out _)) { isActive = true; validUntil = null; return true; }

      invalidReason = "token_invalid_or_unverifiable";
      return false;
    }

    #endregion

    #region " Internal Helpers & private DTOs "

    private string GetConfig(string key, string fallback) {
      if (this.Configuration.TryGetValue(key, out string value) && !String.IsNullOrWhiteSpace(value)) return value;
      return fallback;
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
      string plusFixed = s.Replace("+", "%20", StringComparison.Ordinal);
      return Uri.UnescapeDataString(plusFixed);
    }

    private bool ExchangeCodeForTokens(
        string code, string redirectUri,
        string clientId, string clientSecret,
        out TokenIssuingResult result) {
      result = new TokenIssuingResult();

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["grant_type"] = "authorization_code",
        ["code"] = code,
        ["redirect_uri"] = redirectUri,
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret
        // "scope" ist bei v2 optional; wir lassen es weg, da es im Code steckt.
      };

      var req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", $"{_MsLoginBase}/{_MsTenantDefault}/{_TokenPath}"));
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
        try { err = JsonSerializer.Deserialize<TokenErrorResponse>(body); } catch { /* ignore */ }

        result.error = err != null && !String.IsNullOrWhiteSpace(err.Error) ? err.Error : "token_endpoint_error";
        result.error_description = (err != null && !String.IsNullOrWhiteSpace(err.ErrorDescription))
          ? err.ErrorDescription
          : "Token endpoint returned " + ((int)resp.StatusCode).ToString(CultureInfo.InvariantCulture) + " " + resp.ReasonPhrase;

        return false;
      }

      TokenSuccessResponse data = null;
      try {
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        data = JsonSerializer.Deserialize<TokenSuccessResponse>(body, options);
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

    private bool TryCallTokenInfo(string accessToken, out TokenInfoResponse tokenInfo) {
      // Kein offizielles tokeninfo – wir versuchen JWT zu lesen.
      tokenInfo = null;
      var jwt = TryDecodeJwtWithoutValidation(accessToken);
      if (jwt == null) return false;

      int? expiresIn = null;
      if (jwt.TryGetValue("exp", out var expObj) && expObj != null && Int64.TryParse(Convert.ToString(expObj, CultureInfo.InvariantCulture), out long expUnix)) {
        var dt = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
        expiresIn = (int)Math.Round((dt - DateTime.UtcNow).TotalSeconds);
      }

      string scope = null;
      if (jwt.TryGetValue("scp", out var scpObj) && scpObj != null) scope = Convert.ToString(scpObj, CultureInfo.InvariantCulture);
      // App-Rollen (falls vorhanden)
      if (String.IsNullOrWhiteSpace(scope) && jwt.TryGetValue("roles", out var rolesObj) && rolesObj is object[] arr && arr.Length > 0) {
        scope = String.Join(" ", arr.Select(o => Convert.ToString(o, CultureInfo.InvariantCulture)));
      }

      string aud = jwt.TryGetValue("aud", out var audObj) ? Convert.ToString(audObj, CultureInfo.InvariantCulture) : null;

      string sub = null;
      if (jwt.TryGetValue("sub", out var subObj) && subObj != null) sub = Convert.ToString(subObj, CultureInfo.InvariantCulture);
      else if (jwt.TryGetValue("oid", out var oidObj) && oidObj != null) sub = Convert.ToString(oidObj, CultureInfo.InvariantCulture);

      tokenInfo = new TokenInfoResponse {
        Aud = aud,
        Scope = scope,
        ExpiresIn = expiresIn,
        Sub = sub,
        UserId = sub
      };
      return true;
    }

    private bool TryCallUserInfo(string accessToken, out UserInfoResponse userinfo) {
      userinfo = null;

      // 1) OIDC UserInfo über Graph
      var req = new HttpRequestMessage(HttpMethod.Get, this.GetConfig("userinfo_endpoint", _MsGraphUserInfo));
      req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      try {
        var resp = this.HttpClient.SendAsync(req).GetAwaiter().GetResult();
        var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (resp.StatusCode == HttpStatusCode.OK) {
          var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
          userinfo = JsonSerializer.Deserialize<UserInfoResponse>(body, options) ?? new UserInfoResponse();
          return !String.IsNullOrWhiteSpace(userinfo.Sub);
        }
      }
      catch { /* ignore and fallback */ }

      // 2) Fallback auf /me
      var reqMe = new HttpRequestMessage(HttpMethod.Get, _MsGraphMe);
      reqMe.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      try {
        var resp = this.HttpClient.SendAsync(reqMe).GetAwaiter().GetResult();
        var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (resp.StatusCode != HttpStatusCode.OK) return false;

        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var me = JsonSerializer.Deserialize<MsGraphMe>(body, options) ?? new MsGraphMe();

        // Mapping
        userinfo = new UserInfoResponse {
          Sub = me.Id,
          Name = me.DisplayName ?? me.UserPrincipalName,
          Email = me.Mail ?? me.UserPrincipalName,
          GivenName = me.GivenName,
          FamilyName = me.Surname
        };
        // email_verified unbekannt; Picture nicht verfügbar ohne weiteren Call
        return !String.IsNullOrWhiteSpace(userinfo.Sub);
      }
      catch { return false; }
    }

    private static Dictionary<string, object> TryDecodeJwtWithoutValidation(string jwt) {
      try {
        var parts = jwt.Split('.');
        if (parts.Length < 2) return null;
        var payload = parts[1];
        var payloadBytes = Base64UrlDecode(payload);
        var json = Encoding.UTF8.GetString(payloadBytes);

        using var doc = JsonDocument.Parse(json);
        var dict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var p in doc.RootElement.EnumerateObject()) {
          dict[p.Name] = JsonElementToDotNet(p.Value);
        }
        return dict;
      }
      catch { return null; }
    }

    private static object JsonElementToDotNet(JsonElement el) {
      switch (el.ValueKind) {
        case JsonValueKind.String: return el.GetString();
        case JsonValueKind.Number:
          if (el.TryGetInt64(out long l)) return l;
          if (el.TryGetDouble(out double d)) return d;
          return el.GetRawText();
        case JsonValueKind.True: return true;
        case JsonValueKind.False: return false;
        case JsonValueKind.Array:
          var list = new List<object>();
          foreach (var item in el.EnumerateArray()) list.Add(JsonElementToDotNet(item));
          return list.ToArray();
        case JsonValueKind.Object:
          var obj = new Dictionary<string, object>(StringComparer.Ordinal);
          foreach (var p in el.EnumerateObject()) obj[p.Name] = JsonElementToDotNet(p.Value);
          return obj;
        default: return null;
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

    private static string[] ExtractScopes(Dictionary<string, object> jwt) {
      if (jwt.TryGetValue("scp", out var scpObj) && scpObj != null) {
        var scp = Convert.ToString(scpObj, CultureInfo.InvariantCulture);
        return scp.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
      }
      if (jwt.TryGetValue("roles", out var rolesObj) && rolesObj is object[] arr && arr.Length > 0) {
        return arr.Select(o => Convert.ToString(o, CultureInfo.InvariantCulture)).ToArray();
      }
      return new string[0];
    }

    private static string ExtractSubject(Dictionary<string, object> jwt) {
      if (jwt.TryGetValue("sub", out var subObj) && subObj != null) return Convert.ToString(subObj, CultureInfo.InvariantCulture);
      if (jwt.TryGetValue("oid", out var oidObj) && oidObj != null) return Convert.ToString(oidObj, CultureInfo.InvariantCulture);
      return null;
    }

    private static Dictionary<string, object> BuildAdditionalFromJwt(Dictionary<string, object> jwt) {
      var add = new Dictionary<string, object>(StringComparer.Ordinal);
      if (jwt.TryGetValue("aud", out var audObj) && audObj != null) add["aud"] = Convert.ToString(audObj, CultureInfo.InvariantCulture);
      if (jwt.TryGetValue("exp", out var expObj) && expObj != null && Int64.TryParse(Convert.ToString(expObj, CultureInfo.InvariantCulture), out long expUnix)) {
        var dt = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
        var seconds = (int)Math.Round((dt - DateTime.UtcNow).TotalSeconds);
        add["expires_in"] = seconds;
      }
      if (jwt.TryGetValue("scp", out var scpObj) && scpObj != null) add["scope"] = Convert.ToString(scpObj, CultureInfo.InvariantCulture);
      return add;
    }

    private static void Merge(ref Dictionary<string, object> target, Dictionary<string, object> source) {
      if (source == null) return;
      target ??= new Dictionary<string, object>(StringComparer.Ordinal);
      foreach (var kv in source) target[kv.Key] = kv.Value;
    }


    // ---------------- DTOs ----------------

    private sealed class TokenSuccessResponse {
      [JsonPropertyName("access_token")]
      public string AccessToken { get; set; }

      [JsonPropertyName("expires_in")]
      public int? ExpiresIn { get; set; }

      [JsonPropertyName("refresh_token")]
      public string RefreshToken { get; set; }

      [JsonPropertyName("scope")]
      public string Scope { get; set; }

      [JsonPropertyName("token_type")]
      public string TokenType { get; set; }

      [JsonPropertyName("id_token")]
      public string IdToken { get; set; }
    }

    private sealed class TokenErrorResponse {
      [JsonPropertyName("error")]
      public string Error { get; set; }

      [JsonPropertyName("error_description")]
      public string ErrorDescription { get; set; }
    }

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

    private sealed class UserInfoResponse {
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

      // Microsoft-spezifische Alternativfelder (für Fallback /me)
      [JsonPropertyName("preferred_username")]
      public string PreferredUsername { get; set; }

      public Dictionary<string, object> ToDictionary() {
        var dict = new Dictionary<string, object>(StringComparer.Ordinal);
        if (!String.IsNullOrWhiteSpace(this.Sub)) { dict["sub"] = this.Sub; }
        if (!String.IsNullOrWhiteSpace(this.Email)) { dict["email"] = this.Email; }
        if (this.EmailVerified.HasValue) { dict["email_verified"] = this.EmailVerified.Value; }
        if (!String.IsNullOrWhiteSpace(this.Name)) { dict["name"] = this.Name; }
        if (!String.IsNullOrWhiteSpace(this.Picture)) { dict["picture"] = this.Picture; }
        if (!String.IsNullOrWhiteSpace(this.GivenName)) { dict["given_name"] = this.GivenName; }
        if (!String.IsNullOrWhiteSpace(this.FamilyName)) { dict["family_name"] = this.FamilyName; }
        if (!String.IsNullOrWhiteSpace(this.PreferredUsername)) { dict["preferred_username"] = this.PreferredUsername; }
        return dict;
      }
    }

    private sealed class MsGraphMe {
      [JsonPropertyName("id")] public string Id { get; set; }
      [JsonPropertyName("userPrincipalName")] public string UserPrincipalName { get; set; }
      [JsonPropertyName("mail")] public string Mail { get; set; }
      [JsonPropertyName("givenName")] public string GivenName { get; set; }
      [JsonPropertyName("surname")] public string Surname { get; set; }
      [JsonPropertyName("displayName")] public string DisplayName { get; set; }
    }

    #endregion
  }
}

#endif
