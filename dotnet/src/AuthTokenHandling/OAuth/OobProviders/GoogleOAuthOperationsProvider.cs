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
using System.Xml.Linq;
#if NET5_0_OR_GREATER
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Security.AccessTokenHandling.OAuth.OobProviders {

  public class GoogleOAuthOperationsProvider : IOAuthOperationsProvider, IDisposable {

    private const string _GoogleAuthEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private const string _GoogleTokenEndpoint = "https://oauth2.googleapis.com/token";
    private const string _GoogleTokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo";
    private const string _GoogleUserInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo";

    #region " Matadata & Config "

    private const string _GoogleIconUrl = "data:image/png;base64,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";

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
        return "google"; 
      }
    }

    public string ProviderDisplayTitle {
      get { 
        return "Google";
      }
    }

    public string ProviderIconUrl {
      get {
        string configured;
        if (this.Configuration.TryGetValue("provider_icon_url", out configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return _GoogleIconUrl;
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

    public GoogleOAuthOperationsProvider()
      : this(OAuthOperationsProviderCommonSetupHelper.DefaultHttpClientFactory) {
    }

    public GoogleOAuthOperationsProvider(Func<IOAuthOperationsProvider, HttpClient> httpClientFactory) {
      this.HttpClientFactory = httpClientFactory;

      this.Configuration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      this.Configuration["authorization_endpoint"] = _GoogleAuthEndpoint;
      this.Configuration["token_endpoint"] = _GoogleTokenEndpoint;
      this.Configuration["tokeninfo_endpoint"] = _GoogleTokenInfoEndpoint;
      this.Configuration["userinfo_endpoint"] = _GoogleUserInfoEndpoint;
      this.Configuration["nonce"] = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

    }

    #region " Entry-URL generation "

    public string GenerateEntryUrlForOAuthCodeGrant(
        string clientId, string redirectUri,
        bool requestRefreshToken, bool requestIdToken,
        string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    ) {

      if (String.IsNullOrWhiteSpace(clientId)) {
        throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      }

      if (String.IsNullOrWhiteSpace(redirectUri)) {
        throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      }

      if (scopes == null || scopes.Length == 0) {
        throw new ArgumentException("At least one scope is required.", nameof(scopes));
      }

      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", _GoogleAuthEndpoint));
      url.Append("?response_type=code");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(String.Join(" ", scopes)));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      if (requestRefreshToken) {
        // Für Refresh-Token: offline + prompt=consent (i. d. R. notwendig).
        url.Append("&access_type=offline");
        url.Append("&prompt=consent");
      }

      if (requestIdToken) {
        // Nonce nur aus Configuration; keine Auto-Generierung.
        string nonce;
        if (this.Configuration.TryGetValue("nonce", out nonce) && !String.IsNullOrWhiteSpace(nonce)) {
          url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
        }
      }

      url.Append("&include_granted_scopes=true");

      return url.ToString();
    }

    [Obsolete("Implicit Grant is deprecated.")]
    public string GenerateEntryUrlForOAuthImplicitGrant(
      string clientId, string redirectUri,
      bool requestRefreshToken, bool requestIdToken,
      string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    ) {

      if (String.IsNullOrWhiteSpace(clientId)) {
        throw new ArgumentException("clientId must not be empty.", nameof(clientId));
      }

      if (String.IsNullOrWhiteSpace(redirectUri)) {
        throw new ArgumentException("redirectUri must not be empty.", nameof(redirectUri));
      }

      if (scopes == null || scopes.Length == 0) {
        throw new ArgumentException("At least one scope is required.", nameof(scopes));
      }

      // Hinweis: Im Implicit-Flow gibt es keinen Refresh-Token, daher ignoriert.
      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", _GoogleAuthEndpoint));
      if (requestIdToken) {
        url.Append("?response_type=id_token%20token");
      }
      else {
        url.Append("?response_type=token");
      }

      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));
      url.Append("&scope=").Append(Uri.EscapeDataString(String.Join(" ", scopes)));

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      if (requestIdToken) {
        string nonce;
        if (this.Configuration.TryGetValue("nonce", out nonce) && !String.IsNullOrWhiteSpace(nonce)) {
          url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
        }
      }

      url.Append("&include_granted_scopes=true");

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

      // 1) Implicit-Flow: Tokens im Fragment (#access_token=...&id_token=...)
      if (!String.IsNullOrEmpty(uri.Fragment)) {
        Dictionary<string, string> fragmentValues = ParseFormStyle(uri.Fragment.TrimStart('#'));
        bool anyToken = false;

        if (fragmentValues.ContainsKey("access_token")) {
          result.access_token = fragmentValues["access_token"];
          anyToken = true;
        }

        if (fragmentValues.ContainsKey("id_token")) {
          result.id_token = fragmentValues["id_token"];
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

      // redirect_uri für /token muss exakt passen: wir nehmen die URL ohne Query/Fragment.
      string redirectUriAgain = RemoveQueryAndFragment(uri);
      string code = queryValues["code"];

      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) {
        // Laut XML-Doku dieser Methode: Exception auslösen, wenn Code vorliegt aber Secret fehlt.
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
        error_description = "Google does not support client_credentials for end-user data. Use Service Accounts (JWT/server-to-server) instead."
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

      if (String.IsNullOrWhiteSpace(clientId)) {
        result.error = "missing_client_id";
        result.error_description = "clientId must be provided to refresh tokens with Google.";
        return false;
      }

      Dictionary<string, string> form = new Dictionary<string, string>(StringComparer.Ordinal);
      form["grant_type"] = "refresh_token";
      form["refresh_token"] = refreshToken;
      form["client_id"] = clientId;
      if (!String.IsNullOrWhiteSpace(clientSecret)) {
        form["client_secret"] = clientSecret;
      }

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", _GoogleTokenEndpoint));
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

      if (!String.IsNullOrWhiteSpace(tokenInfo.Scope)) {
        scopes = tokenInfo.Scope.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
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
        bool hasOpenId = false;
        for (int i = 0; i < scopes.Length; i++) {
          if (String.Equals(scopes[i], "openid", StringComparison.Ordinal)) {
            hasOpenId = true;
            break;
          }
        }

        if (hasOpenId) {
          UserInfoResponse userinfo;
          if (this.TryCallUserInfo(accessToken, out userinfo)) {
            subject = userinfo.Sub;
            additionalClaims = userinfo.ToDictionary();
          }
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
        scopes = tokenInfo.Scope.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
      }
      else {
        scopes = new string[0];
      }

      Dictionary<string, object> idClaims = null;

      if (!String.IsNullOrWhiteSpace(idToken)) {
        idClaims = TryDecodeJwtWithoutValidation(idToken);
        if (idClaims != null && idClaims.ContainsKey("sub")) {
          object subObj = idClaims["sub"];
          if (subObj != null) {
            subject = Convert.ToString(subObj, CultureInfo.InvariantCulture);
          }
        }
      }

      if (String.IsNullOrWhiteSpace(subject) && !String.IsNullOrWhiteSpace(accessToken)) {
        bool hasOpenId = false;
        for (int i = 0; i < scopes.Length; i++) {
          if (String.Equals(scopes[i], "openid", StringComparison.Ordinal)) {
            hasOpenId = true;
            break;
          }
        }

        if (hasOpenId) {
          UserInfoResponse userinfo;
          if (this.TryCallUserInfo(accessToken, out userinfo)) {
            subject = userinfo.Sub;
            if (additionalClaims == null) {
              additionalClaims = userinfo.ToDictionary();
            }
          }
        }
      }

      if (additionalClaims == null) {
        additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      }

      if (idClaims != null) {
        foreach (KeyValuePair<string, object> kv in idClaims) {
          additionalClaims[kv.Key] = kv.Value;
        }
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
        invalidReason = "tokeninfo endpoint not reachable or returned an unexpected response.";
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

      // RFC 3986: '+' ist im Query form-url-encoded als Leerzeichen vorgesehen.
      // Für OAuth-Response-Fragmente/Queries behandeln wir '+' als '%20'.
      string plusFixed = s.Replace("+", "%20", StringComparison.Ordinal);
      return Uri.UnescapeDataString(plusFixed);
    }

    private bool ExchangeCodeForTokens(
        string code, string redirectUri,
        string clientId, string clientSecret,
        out TokenIssuingResult result) {
      result = new TokenIssuingResult();

      Dictionary<string, string> form = new Dictionary<string, string>(StringComparer.Ordinal);
      form["grant_type"] = "authorization_code";
      form["code"] = code;
      form["redirect_uri"] = redirectUri;
      form["client_id"] = clientId;
      form["client_secret"] = clientSecret;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", _GoogleTokenEndpoint));
      req.Content = new FormUrlEncodedContent(form);

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

      //result.RawResponse = body;

      if (resp.StatusCode != HttpStatusCode.OK) {
        TokenErrorResponse err = null;
        try {
          err = JsonSerializer.Deserialize<TokenErrorResponse>(body);
        }
        catch {
          // Ignorieren – wir generieren eine generische Meldung
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
      result.refresh_token = data.RefreshToken;
      result.id_token = data.IdToken;
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

      string url = this.GetConfig("tokeninfo_endpoint", _GoogleTokenInfoEndpoint) + "?access_token=" + Uri.EscapeDataString(accessToken);
      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, url);

      try {
        HttpResponseMessage resp = this._HttpClient.SendAsync(req).Result;
        string body = resp.Content.ReadAsStringAsync().Result;

        if (resp.StatusCode != HttpStatusCode.OK) {
          return false;
        }

        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;

        tokenInfo = JsonSerializer.Deserialize<TokenInfoResponse>(body, options);
        return tokenInfo != null;
      }
      catch {
        return false;
      }
    }

    private bool TryCallUserInfo(string accessToken, out UserInfoResponse userinfo) {
      userinfo = null;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, this.GetConfig("userinfo_endpoint", _GoogleUserInfoEndpoint));
      req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

      try {
        HttpResponseMessage resp = this._HttpClient.SendAsync(req).Result;
        string body = resp.Content.ReadAsStringAsync().Result;

        if (resp.StatusCode != HttpStatusCode.OK) {
          return false;
        }

        JsonSerializerOptions options = new JsonSerializerOptions();
        options.PropertyNameCaseInsensitive = true;

        userinfo = JsonSerializer.Deserialize<UserInfoResponse>(body, options);
        return userinfo != null && !String.IsNullOrWhiteSpace(userinfo.Sub);
      }
      catch {
        return false;
      }
    }

    private static Dictionary<string, object> TryDecodeJwtWithoutValidation(string jwt) {
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

      // tokeninfo liefert ggf. "sub" oder "user_id" (nicht garantiert)
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

      public Dictionary<string, object> ToDictionary() {
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
 
  #endregion

  }

}

#endif
