using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth.Server;
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

  public class GitHubOAuthOperationsProvider : IOAuthOperationsProvider, IDisposable {

    private const string _GitHubAuthorizeEndpoint = "https://github.com/login/oauth/authorize";
    private const string _GitHubTokenEndpoint = "https://github.com/login/oauth/access_token";

    // Kein echtes Token-Info-Endpoint bei GitHub – wir verwenden /user

    private const string _GitHubUserEndpoint = "https://api.github.com/user";

    private const string _GitHubApiVersion = "2022-11-28";

    private static readonly ProductInfoHeaderValue _UserAgent = new ProductInfoHeaderValue("UniversalBFF-OAuthClient", "1.0");

    #region " Matadata & Config "

    private const string _GitHubIconUrl = "data:image/png;base64,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";

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
        return "github";
      }
    }

    public string ProviderDisplayTitle {
      get {
        return "GitHub";
      }
    }

    public string ProviderIconUrl {
      get {
        string configured;
        if (this.Configuration.TryGetValue("provider_icon_url", out configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return _GitHubIconUrl;
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

    public void Dispose() {
      if (_HttpClient != null) {
        _HttpClient.Dispose();
      }
    }

    #endregion

    public GitHubOAuthOperationsProvider()
      : this(OAuthOperationsProviderCommonSetupHelper.DefaultHttpClientFactory) {
    }


    public GitHubOAuthOperationsProvider(Func<IOAuthOperationsProvider, HttpClient> httpClientFactory) {
      this.HttpClientFactory = httpClientFactory;

      this.Configuration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      this.Configuration["authorization_endpoint"] = _GitHubAuthorizeEndpoint;
      this.Configuration["token_endpoint"] = _GitHubTokenEndpoint;
      this.Configuration["tokeninfo_endpoint"] = _GitHubUserEndpoint; // Platzhalter – tatsächliche Prüfung via /user
      this.Configuration["userinfo_endpoint"] = _GitHubUserEndpoint;
      this.Configuration["nonce"] = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
      // Optional überschreibbar:
      // this.Configuration["api_version"] = "2022-11-28";

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

      // GitHub erwartet space-separierte Scopes
      string scopeJoined = String.Join(" ", scopes);

      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", _GitHubAuthorizeEndpoint));
      url.Append("?response_type=code");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      // GitHub: requestIdToken/Refresh werden ignoriert (kein OIDC, Refresh nur später am Token-Endpoint)

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

      // GitHub unterstützt Implicit nicht – wir erzeugen trotzdem eine URL mit response_type=token (ohne Garantie).
      string scopeJoined = String.Join(" ", scopes);

      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", _GitHubAuthorizeEndpoint));
      url.Append("?response_type=token");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
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

      Uri uri;
      if (!Uri.TryCreate(finalUrlFromAuthFlow, UriKind.Absolute, out uri)) {
        result.error = "invalid_argument";
        result.error_description = "finalUrlFromAuthFlow is not a valid absolute URI.";
        return false;
      }

      // 1) Implicit-Flow (GitHub nicht offiziell): Tokens im Fragment (#access_token=...)
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

        // GitHub liefert kein id_token
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

      result = new TokenIssuingResult {
        error = "unsupported_grant_type",
        error_description = "GitHub does not support client_credentials for user data."
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

      // GitHub Refresh (nur wenn 'Expiring user tokens' aktiv ist)
      Dictionary<string, string> form = new Dictionary<string, string>(StringComparer.Ordinal);
      form["grant_type"] = "refresh_token";
      form["refresh_token"] = refreshToken;
      form["client_id"] = clientId;
      form["client_secret"] = clientSecret;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", _GitHubTokenEndpoint));
      req.Content = new FormUrlEncodedContent(form);
      req.Headers.Accept.Clear();
      req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

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

      subject = null;
      scopes = null;
      additionalClaims = null;

      if (String.IsNullOrWhiteSpace(accessToken)) {
        return false;
      }

      TokenInfoResponse tokenInfo;
      if (!this.TryCallTokenInfo(accessToken, out tokenInfo)) {
        return false;
      }

      scopes = tokenInfo.Scope != null
        ? tokenInfo.Scope.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
        : new string[0];

      if (!String.IsNullOrWhiteSpace(tokenInfo.Sub)) {
        subject = tokenInfo.Sub;
      }
      else if (!String.IsNullOrWhiteSpace(tokenInfo.UserId)) {
        subject = tokenInfo.UserId;
      }

      // Zusätzliche Claims via /user (Name, Login, Avatar, Email falls vorhanden)
      UserInfoResponse userinfo;
      if (this.TryCallUserInfo(accessToken, out userinfo)) {
        if (String.IsNullOrWhiteSpace(subject)) {
          subject = userinfo.Sub;
        }
        additionalClaims = userinfo.ToDictionary();
      }

      if (additionalClaims == null) {
        additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      }

      additionalClaims["aud"] = "github";
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

      // GitHub liefert kein id_token – Parameter wird ignoriert.
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

      if (tokenInfo != null) {
        if (!String.IsNullOrWhiteSpace(tokenInfo.Sub)) {
          subject = tokenInfo.Sub;
        }
        else if (!String.IsNullOrWhiteSpace(tokenInfo.UserId)) {
          subject = tokenInfo.UserId;
        }
      }

      UserInfoResponse userinfo;
      if (this.TryCallUserInfo(accessToken, out userinfo)) {
        if (String.IsNullOrWhiteSpace(subject)) {
          subject = userinfo.Sub;
        }
        if (additionalClaims == null) {
          additionalClaims = userinfo.ToDictionary();
        }
      }

      if (additionalClaims == null) {
        additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      }

      additionalClaims["aud"] = "github";
      if (tokenInfo != null) {
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
        invalidReason = "userinfo endpoint not reachable or token invalid.";
        return false;
      }

      // GitHub-User-Call erfolgreich ⇒ Token aktiv. Expiry ist i. d. R. nicht verfügbar.
      isActive = true;
      validUntil = null;
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

      var form = new Dictionary<string, string>(StringComparer.Ordinal) {
        ["code"] = code,
        ["redirect_uri"] = redirectUri,
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret
      };

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", _GitHubTokenEndpoint));
      req.Content = new FormUrlEncodedContent(form);
      req.Headers.Accept.Clear();
      req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

      return this.SendTokenRequest(req, out result);
    }

    private bool SendTokenRequest(HttpRequestMessage request, out TokenIssuingResult result) {
      result = new TokenIssuingResult();

      HttpResponseMessage resp = null;
      string body = null;

      try {
        resp = this._HttpClient.SendAsync(request).Result;
        body = resp.Content.ReadAsStringAsync().Result;
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
          // ignorieren
        }

        result.error = err != null && !String.IsNullOrWhiteSpace(err.Error) ? err.Error : "token_endpoint_error";
        result.error_description = (err != null && !String.IsNullOrWhiteSpace(err.ErrorDescription))
          ? err.ErrorDescription
          : "Token endpoint returned " + ((int)resp.StatusCode).ToString(CultureInfo.InvariantCulture) + " " + resp.ReasonPhrase;

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
      result.refresh_token = data.RefreshToken; // nur vorhanden, falls Expiring Tokens aktiviert
      result.id_token = null; // GitHub hat kein ID Token
      result.token_type = data.TokenType;
      if (data.ExpiresIn.HasValue) {
        result.expires_in = data.ExpiresIn.Value;
      }

      if (!String.IsNullOrWhiteSpace(data.Scope)) {
        result.scope = data.Scope; // GitHub liefert meist kommagetrennt (z. B. "repo,gist")
      }

      return true;
    }

    private bool TryCallTokenInfo(string accessToken, out TokenInfoResponse tokenInfo) {
      tokenInfo = null;

      // Wir rufen /user auf. Bei 200 OK ist Token gültig.
      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, this.GetConfig("tokeninfo_endpoint", _GitHubUserEndpoint));
      req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
      req.Headers.UserAgent.Add(_UserAgent);
      string apiVersion = this.GetConfig("api_version", _GitHubApiVersion);
      if (!String.IsNullOrWhiteSpace(apiVersion)) {
        req.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", apiVersion);
      }

      try {
        HttpResponseMessage resp = this._HttpClient.SendAsync(req).Result;
        string body = resp.Content.ReadAsStringAsync().Result;

        if (resp.StatusCode != HttpStatusCode.OK) {
          return false;
        }

        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;

        var user = JsonSerializer.Deserialize<UserInfoResponse>(body, options);

        // Scopes aus Response-Header X-OAuth-Scopes
        string scopeHeader = null;
        if (resp.Headers.TryGetValues("X-OAuth-Scopes", out IEnumerable<string> scopeValues)) {
          scopeHeader = String.Join(",", scopeValues);
        }

        tokenInfo = new TokenInfoResponse {
          Aud = "github",
          Scope = scopeHeader,
          ExpiresIn = null, // GitHub liefert hier nichts
          Sub = user != null ? user.Id?.ToString(CultureInfo.InvariantCulture) : null,
          UserId = user != null ? user.Id?.ToString(CultureInfo.InvariantCulture) : null
        };
        return true;
      }
      catch {
        return false;
      }
    }

    private bool TryCallUserInfo(string accessToken, out UserInfoResponse userinfo) {
      userinfo = null;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, this.GetConfig("userinfo_endpoint", _GitHubUserEndpoint));
      req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
      req.Headers.UserAgent.Add(_UserAgent);
      string apiVersion = this.GetConfig("api_version", _GitHubApiVersion);
      if (!String.IsNullOrWhiteSpace(apiVersion)) {
        req.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", apiVersion);
      }

      try {
        HttpResponseMessage resp = this._HttpClient.SendAsync(req).Result;
        string body = resp.Content.ReadAsStringAsync().Result;

        if (resp.StatusCode != HttpStatusCode.OK) {
          return false;
        }

        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;

        userinfo = JsonSerializer.Deserialize<UserInfoResponse>(body, options) ?? new UserInfoResponse();

        if (userinfo != null) {
          if (String.IsNullOrWhiteSpace(userinfo.Sub) && userinfo.Id.HasValue) {
            userinfo.Sub = userinfo.Id.Value.ToString(CultureInfo.InvariantCulture);
          }
          if (String.IsNullOrWhiteSpace(userinfo.Picture) && !String.IsNullOrWhiteSpace(userinfo.AvatarUrl)) {
            userinfo.Picture = userinfo.AvatarUrl;
          }
          if (String.IsNullOrWhiteSpace(userinfo.Name) && !String.IsNullOrWhiteSpace(userinfo.Login)) {
            userinfo.Name = userinfo.Login;
          }
        }

        return userinfo != null && !String.IsNullOrWhiteSpace(userinfo.Sub);
      }
      catch {
        return false;
      }
    }

    private static Dictionary<string, object> TryDecodeJwtWithoutValidation(string jwt) {
      // Wird bei GitHub nicht benötigt (kein ID Token); Methode bleibt der Schnittstelle halber bestehen.
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

    // ---------------- DTOs ----------------

    private sealed class TokenSuccessResponse {
      [JsonPropertyName("access_token")]
      public string AccessToken { get; set; }

      [JsonPropertyName("expires_in")]
      public int? ExpiresIn { get; set; }

      [JsonPropertyName("refresh_token")]
      public string RefreshToken { get; set; }

      // GitHub liefert Scopes meist kommagetrennt ("repo,gist")
      [JsonPropertyName("scope")]
      public string Scope { get; set; }

      [JsonPropertyName("token_type")]
      public string TokenType { get; set; }

      // Nicht vorhanden bei GitHub
      [JsonPropertyName("id_token")]
      public string IdToken { get; set; }

      // Optional bei GitHub
      [JsonPropertyName("refresh_token_expires_in")]
      public int? RefreshTokenExpiresIn { get; set; }
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
      // OIDC-kompatible Felder (gemappt)
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

      // GitHub-spezifisch
      [JsonPropertyName("id")]
      public long? Id { get; set; }

      [JsonPropertyName("login")]
      public string Login { get; set; }

      [JsonPropertyName("avatar_url")]
      public string AvatarUrl { get; set; }

      public Dictionary<string, object> ToDictionary() {
        if (String.IsNullOrWhiteSpace(this.Sub) && this.Id.HasValue) this.Sub = this.Id.Value.ToString(CultureInfo.InvariantCulture);
        if (String.IsNullOrWhiteSpace(this.Picture) && !String.IsNullOrWhiteSpace(this.AvatarUrl)) this.Picture = this.AvatarUrl;
        if (String.IsNullOrWhiteSpace(this.Name) && !String.IsNullOrWhiteSpace(this.Login)) this.Name = this.Login;

        Dictionary<string, object> dict = new Dictionary<string, object>(StringComparer.Ordinal);
        if (!String.IsNullOrWhiteSpace(this.Sub)) { dict["sub"] = this.Sub; }
        if (!String.IsNullOrWhiteSpace(this.Email)) { dict["email"] = this.Email; }
        if (this.EmailVerified.HasValue) { dict["email_verified"] = this.EmailVerified.Value; }
        if (!String.IsNullOrWhiteSpace(this.Name)) { dict["name"] = this.Name; }
        if (!String.IsNullOrWhiteSpace(this.Picture)) { dict["picture"] = this.Picture; }
        if (!String.IsNullOrWhiteSpace(this.GivenName)) { dict["given_name"] = this.GivenName; }
        if (!String.IsNullOrWhiteSpace(this.FamilyName)) { dict["family_name"] = this.FamilyName; }
        if (!String.IsNullOrWhiteSpace(this.Login)) { dict["login"] = this.Login; }
        return dict;
      }
    }

    #endregion

  }

}

#endif