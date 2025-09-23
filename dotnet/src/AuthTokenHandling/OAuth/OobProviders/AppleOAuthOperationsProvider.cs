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

  public class AppleOAuthOperationsProvider : IOAuthOperationsProvider, IDisposable {

    // --- Apple Defaults ---
    private const string _AppleAuthorizeEndpoint = "https://appleid.apple.com/auth/authorize";
    private const string _AppleTokenEndpoint = "https://appleid.apple.com/auth/token";
    // Apple stellt KEIN tokeninfo/userinfo bereit; JWKS existiert, wird hier aber nicht genutzt.
    private const string _AppleJWKS = "https://appleid.apple.com/auth/keys";

    #region " Matadata & Config "

    private const string _AppleIconUrl = "data:image/png;base64,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";

    public Dictionary<string, string> Configuration { get; } = new Dictionary<string, string>();

    public string ProviderInvariantName {
      get {
        return "apple";
      }
    }

    public string ProviderDisplayTitle {
      get {
        return "Apple";
      }
    }

    public string ProviderIconUrl {
      get {
        string configured;
        if (this.Configuration.TryGetValue("provider_icon_url", out configured) && !String.IsNullOrWhiteSpace(configured)) {
          return configured;
        }
        return _AppleIconUrl;
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

    private readonly HttpClient _HttpClient;

    public void Dispose() {
      if (_HttpClient != null) {
        _HttpClient.Dispose();
      }
    }

    public AppleOAuthOperationsProvider()
      : this(new HttpClient()) {
    }

    public AppleOAuthOperationsProvider(HttpClient httpClient) {

      if (httpClient == null) {
        throw new ArgumentNullException(nameof(httpClient));
      }

      this._HttpClient = httpClient;

      this.Configuration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      this.Configuration["authorization_endpoint"] = _AppleAuthorizeEndpoint;
      this.Configuration["token_endpoint"] = _AppleTokenEndpoint;
      // „tokeninfo“/„userinfo“ hat Apple nicht; Einträge bleiben der API wegen bestehen.
      this.Configuration["tokeninfo_endpoint"] = _AppleJWKS;   // Platzhalter, wird nicht genutzt
      this.Configuration["userinfo_endpoint"] = "";           // nicht vorhanden
      this.Configuration["nonce"] = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

      // Hinweis: client_secret MUSS ein signiertes JWT (ES256) sein (TeamID/KID/iss/sub/aud).
      // Das JWT lieferst du über die bestehenden Methoden-Parameter (clientSecret).
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
        // Bei Apple können Scopes leer sein; falls gewünscht „name email“
        scopes = Array.Empty<string>();
      }

      // Apple: space-getrennte Scopes (z. B. "name email")
      string scopeJoined = scopes.Length == 0 ? "" : String.Join(" ", scopes);

      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", _AppleAuthorizeEndpoint));
      url.Append("?response_type=code");
      url.Append("&response_mode=query"); // damit dein Code die Query auslesen kann
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));

      if (!String.IsNullOrEmpty(scopeJoined)) {
        url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));
      }

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      // Apple: requestRefreshToken / requestIdToken haben hier keine direkte Auswirkung.
      // (Refresh Token wird ggf. beim Token-Tausch ausgegeben, ID-Token kommt vom Token-Endpoint.)

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

      if (scopes == null) scopes = Array.Empty<string>();
      string scopeJoined = scopes.Length == 0 ? "" : String.Join(" ", scopes);

      // Apple unterstützt id_token-only (OIDC Implicit/Hybrid). Wir verwenden response_mode=fragment,
      // damit dein vorhandener Fragment-Parser greift.
      StringBuilder url = new StringBuilder();
      url.Append(this.GetConfig("authorization_endpoint", _AppleAuthorizeEndpoint));

      if (requestIdToken) {
        url.Append("?response_type=id_token");
      }
      else {
        // reines access_token-Implicit ist bei Apple nicht üblich – wir senden dennoch id_token.
        url.Append("?response_type=id_token");
      }

      url.Append("&response_mode=fragment");
      url.Append("&client_id=").Append(Uri.EscapeDataString(clientId));
      url.Append("&redirect_uri=").Append(Uri.EscapeDataString(redirectUri));

      if (!String.IsNullOrEmpty(scopeJoined)) {
        url.Append("&scope=").Append(Uri.EscapeDataString(scopeJoined));
      }

      if (!String.IsNullOrEmpty(state)) {
        url.Append("&state=").Append(Uri.EscapeDataString(state));
      }

      // Für id_token ist eine Nonce sinnvoll
      string nonce;
      if (this.Configuration.TryGetValue("nonce", out nonce) && !String.IsNullOrWhiteSpace(nonce)) {
        url.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
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

      // 1) Implicit-Flow (id_token im Fragment)
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

      // redirect_uri exakt ohne Query/Fragment
      string redirectUriAgain = RemoveQueryAndFragment(uri);
      string code = queryValues["code"];

      if (String.IsNullOrWhiteSpace(clientId) || String.IsNullOrWhiteSpace(clientSecret)) {
        throw new InvalidOperationException("clientId and clientSecret (Apple JWT) are required to exchange the code for tokens.");
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
        result.error_description = "clientId and clientSecret (Apple JWT) are required.";
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
        error_description = "Apple does not support client_credentials for Sign in with Apple."
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
        result.error_description = "clientId and clientSecret (Apple JWT) are required.";
        return false;
      }

      Dictionary<string, string> form = new Dictionary<string, string>(StringComparer.Ordinal);
      form["grant_type"] = "refresh_token";
      form["refresh_token"] = refreshToken;
      form["client_id"] = clientId;
      form["client_secret"] = clientSecret;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", _AppleTokenEndpoint));
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

      // Apple bietet keine Access-Token-Introspektion/keinen userinfo Endpoint.
      subject = null;
      scopes = new string[0];
      additionalClaims = null;
      return false;
    }

    public bool TryResolveSubjectAndScopes(
      string accessToken, string idToken,
      out string subject, out string[] scopes,
      out Dictionary<string, object> additionalClaims
     ) {

      subject = null;
      scopes = new string[0];
      additionalClaims = null;

      if (String.IsNullOrWhiteSpace(accessToken) && String.IsNullOrWhiteSpace(idToken)) {
        return false;
      }

      Dictionary<string, object> idClaims = null;

      if (!String.IsNullOrWhiteSpace(idToken)) {
        idClaims = TryDecodeJwtWithoutValidation(idToken);
        if (idClaims != null && idClaims.ContainsKey("sub") && idClaims["sub"] != null) {
          subject = Convert.ToString(idClaims["sub"], CultureInfo.InvariantCulture);
        }
      }

      if (additionalClaims == null) {
        additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);
      }

      if (idClaims != null) {
        foreach (KeyValuePair<string, object> kv in idClaims) {
          additionalClaims[kv.Key] = kv.Value;
        }
        // aud / exp / email / email_verified sind typische Apple-Claims
        // scopes sind bei Apple nicht zuverlässig verfügbar → leer lassen.
      }

      return !String.IsNullOrWhiteSpace(subject);
    }

    public bool TryValidateToken(
      string accessToken,
      out bool isActive,
      out DateTime? validUntil,
      out string invalidReason
    ) {

      // Für Apple lässt sich der Access Token ohne ID Token/JWKS-Prüfung nicht introspektieren.
      isActive = false;
      validUntil = null;
      invalidReason = "no_introspection_available_for_access_token";
      return false;
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

      // Apple: grant_type=authorization_code, client_secret = JWT
      Dictionary<string, string> form = new Dictionary<string, string>(StringComparer.Ordinal);
      form["grant_type"] = "authorization_code";
      form["code"] = code;
      form["redirect_uri"] = redirectUri;
      form["client_id"] = clientId;
      form["client_secret"] = clientSecret;

      HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, this.GetConfig("token_endpoint", _AppleTokenEndpoint));
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
      result.refresh_token = data.RefreshToken; // kann beim ersten Tausch kommen
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
      // Apple: kein debug/tokeninfo → nicht verfügbar
      tokenInfo = null;
      return false;
    }

    private bool TryCallUserInfo(string accessToken, out UserInfoResponse userinfo) {
      // Apple: kein userinfo Endpoint
      userinfo = null;
      return false;
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
