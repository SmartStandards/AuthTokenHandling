using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// 'Cheap OAuth Server': a small OAuth 2.1 authorization server logic for the 'OAuth2Controller', which works
  /// out of the box with exactly one credential source (see 'CheapOAuthOptions').
  /// Supported: authorization code flow with mandatory PKCE (S256), one-time codes, rotating refresh tokens
  /// with reuse detection, resource indicators (RFC 8707, returned as claim 'aud').
  /// NOT supported: implicit flow, client credentials, Windows pass-through.
  /// Without persistence all state is held in-memory (login sessions and codes are always in-memory - they live only minutes).
  /// </summary>
  public sealed class CheapOAuthService : IOAuthService {

    private const string _PersistenceSectionName = "refreshGrants";

    private static readonly TimeSpan _SessionLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan _CodeLifetime = TimeSpan.FromMinutes(1);

    private readonly CheapOAuthOptions _Options;
    private readonly CheapOAuthGrantStore _GrantStore;
    private readonly CheapOAuthClientRegistry _ClientRegistry;
    private readonly Func<DateTime> _UtcNow;

    private readonly ConcurrentDictionary<string, LoginSession> _SessionsByHash = new ConcurrentDictionary<string, LoginSession>(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, PendingCode> _CodesByHash = new ConcurrentDictionary<string, PendingCode>(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, RefreshGrant> _RefreshGrantsByHash = new ConcurrentDictionary<string, RefreshGrant>(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _ConsumedRefreshHashesToFamily = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
    private CheapOAuthStatePersistence _Persistence;

    public CheapOAuthService(CheapOAuthOptions options, CheapOAuthGrantStore grantStore, CheapOAuthClientRegistry clientRegistry)
      : this(options, grantStore, clientRegistry, null) {
    }

    /// <summary>
    /// Creates the service with a custom clock (for tests).
    /// </summary>
    public CheapOAuthService(CheapOAuthOptions options, CheapOAuthGrantStore grantStore, CheapOAuthClientRegistry clientRegistry, Func<DateTime> utcNow) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      if (grantStore == null) {
        throw new ArgumentNullException(nameof(grantStore));
      }
      if (clientRegistry == null) {
        throw new ArgumentNullException(nameof(clientRegistry));
      }
      options.Validate();
      _Options = options;
      _GrantStore = grantStore;
      _ClientRegistry = clientRegistry;
      if (utcNow == null) {
        _UtcNow = () => DateTime.UtcNow;
      }
      else {
        _UtcNow = utcNow;
      }
    }

    /// <summary>
    /// The store of the issued access tokens (e.g. to read the retained secret of the current token).
    /// </summary>
    public CheapOAuthGrantStore GrantStore {
      get {
        return _GrantStore;
      }
    }

    /// <summary>
    /// The registry of the known clients.
    /// </summary>
    public CheapOAuthClientRegistry ClientRegistry {
      get {
        return _ClientRegistry;
      }
    }

    #region " Persistence "

    /// <summary>
    /// Restores the persisted (not yet expired) refresh grants including the reuse-detection state and writes
    /// every subsequent change into the given persistence. Only token hashes are persisted - never raw tokens.
    /// </summary>
    public void AttachPersistence(CheapOAuthStatePersistence persistence) {
      if (persistence == null) {
        throw new ArgumentNullException(nameof(persistence));
      }
      DateTime now = _UtcNow();
      JObject section = persistence.Load(_PersistenceSectionName) as JObject;
      if (section != null) {
        JArray grants = section["grants"] as JArray;
        if (grants != null) {
          foreach (JToken token in grants) {
            JObject entry = (JObject)token;
            DateTime expiresUtc = CheapOAuthStatePersistence.FromUnixMilliseconds(entry["exp"]);
            if (expiresUtc <= now) {
              continue;
            }
            _RefreshGrantsByHash[entry.Value<string>("hash")] = new RefreshGrant(
              entry.Value<string>("client"),
              entry.Value<string>("sub"),
              entry.Value<string>("secret"),
              CheapOAuthStatePersistence.ToStringArray(entry["scopes"]),
              entry.Value<string>("resource"),
              entry.Value<string>("family"),
              expiresUtc
            );
          }
        }
        JObject consumed = section["consumed"] as JObject;
        if (consumed != null) {
          foreach (JProperty entry in consumed.Properties()) {
            _ConsumedRefreshHashesToFamily[entry.Name] = entry.Value.ToString();
          }
        }
      }
      _Persistence = persistence;
    }

    private void Persist() {
      CheapOAuthStatePersistence persistence = _Persistence;
      if (persistence == null) {
        return;
      }
      persistence.Save(_PersistenceSectionName, () => {
        JArray grants = new JArray();
        foreach (KeyValuePair<string, RefreshGrant> entry in _RefreshGrantsByHash) {
          JObject item = new JObject();
          item["hash"] = entry.Key;
          item["client"] = entry.Value.ClientId;
          item["sub"] = entry.Value.Subject;
          if (entry.Value.RetainedSecret != null) {
            item["secret"] = entry.Value.RetainedSecret;
          }
          item["scopes"] = CheapOAuthStatePersistence.ToJArray(entry.Value.Scopes);
          item["resource"] = entry.Value.Resource;
          item["family"] = entry.Value.FamilyId;
          item["exp"] = CheapOAuthStatePersistence.ToUnixMilliseconds(entry.Value.ExpiresUtc);
          grants.Add(item);
        }
        JObject consumed = new JObject();
        foreach (KeyValuePair<string, string> entry in _ConsumedRefreshHashesToFamily) {
          consumed[entry.Key] = entry.Value;
        }
        JObject section = new JObject();
        section["grants"] = grants;
        section["consumed"] = consumed;
        return section;
      });
    }

    #endregion

    #region " Login (Step 1) "

    /// <summary>
    /// Validates the credentials via the configured credential source and opens a short-lived login session.
    /// </summary>
    public bool TryAuthenticate(
      string apiClientId, string login, string password, bool noPasswordNeeded, string clientProvidedState,
      out string sessionId, out string message
    ) {
      sessionId = null;
      if (noPasswordNeeded) {
        message = "Pass-through login is not supported. Please enter your credentials.";
        return false;
      }
      if (!_ClientRegistry.IsKnownClient(apiClientId)) {
        message = "Unknown client.";
        return false;
      }
      if (string.IsNullOrWhiteSpace(login) || string.IsNullOrEmpty(password)) {
        message = "Invalid user name or password.";
        return false;
      }

      CheapOAuthLoginResult result = _Options.ValidateLogin.Invoke(login, password);
      if (result == null || result.Kind == CheapOAuthLoginResultKind.Invalid) {
        message = "Invalid user name or password.";
        return false;
      }
      if (result.Kind == CheapOAuthLoginResultKind.BackendUnavailable) {
        message = "The backend server is currently not reachable. Please try again later.";
        return false;
      }

      string[] userScopes = result.Scopes;
      if (userScopes == null) {
        userScopes = _Options.DefaultScopes;
      }
      //symmetry rule: the scopes are granted exactly as they are checked (with the configured prefix)
      userScopes = AccessTokenManager.ApplyApiPermissionPrefix(userScopes);

      this.RemoveExpiredEntries();
      string rawSessionId = CheapOAuthGrantStore.CreateRandomToken();
      _SessionsByHash[CheapOAuthGrantStore.HashToken(rawSessionId)] = new LoginSession(
        apiClientId, login, result.RetainedSecret, userScopes, _UtcNow().Add(_SessionLifetime)
      );
      sessionId = rawSessionId;
      message = null;
      return true;
    }

    /// <summary>
    /// Offers the scopes of the user for confirmation (preselected: the requested ones, or all if none were requested).
    /// </summary>
    public bool TryGetAvailableScopesBySessionId(
      string apiClientId, string sessionId, string[] prefferedScopes,
      out ScopeDescriptor[] availableScopes, out string message
    ) {
      LoginSession session;
      if (!this.TryGetSession(apiClientId, sessionId, false, out session)) {
        availableScopes = new ScopeDescriptor[] { };
        message = "The login session is invalid or expired. Please log in again.";
        return false;
      }
      string[] offered = IntersectScopes(session.Scopes, prefferedScopes, true);
      List<ScopeDescriptor> descriptors = new List<ScopeDescriptor>();
      foreach (string scope in offered) {
        ScopeDescriptor descriptor = new ScopeDescriptor();
        descriptor.Expression = scope;
        descriptor.Label = scope;
        descriptor.Selected = true;
        descriptor.ReadOnly = false;
        descriptor.Invisible = false;
        descriptors.Add(descriptor);
      }
      availableScopes = descriptors.ToArray();
      message = null;
      return true;
    }

    #endregion

    #region " Code Flow (Step 2 + 3) "

    /// <summary>
    /// Consumes the login session and creates a one-time retrieval code which is bound to client,
    /// PKCE challenge and resource. Granted scopes = selected scopes intersected with the scopes of the user.
    /// </summary>
    public bool TryValidateSessionIdAndCreateRetrievalCode(
      string apiClientId, string sessionId, string[] selectedScopes, string codeChallenge, string resource,
      out string code, out string message
    ) {
      code = null;
      if (string.IsNullOrWhiteSpace(codeChallenge)) {
        message = "PKCE (code_challenge with method S256) is required.";
        return false;
      }
      LoginSession session;
      if (!this.TryGetSession(apiClientId, sessionId, true, out session)) {
        message = "The login session is invalid or expired. Please log in again.";
        return false;
      }
      string[] grantedScopes = IntersectScopes(session.Scopes, selectedScopes, false);
      string normalizedResource = resource;
      if (string.IsNullOrWhiteSpace(normalizedResource)) {
        normalizedResource = null;
      }
      string rawCode = CheapOAuthGrantStore.CreateRandomToken();
      _CodesByHash[CheapOAuthGrantStore.HashToken(rawCode)] = new PendingCode(
        apiClientId, session.Subject, session.RetainedSecret, grantedScopes, codeChallenge, normalizedResource, _UtcNow().Add(_CodeLifetime)
      );
      code = rawCode;
      message = null;
      return true;
    }

    /// <summary>
    /// Redeems a one-time code (it is removed in any case) and issues access + refresh token.
    /// The PKCE verification is done by the controller with the returned (bound) code challenge.
    /// </summary>
    public TokenIssuingResult RetrieveTokenByCode(string clientId, string clientSecret, string code, out string codeChallenge, out string resource) {
      codeChallenge = null;
      resource = null;
      if (string.IsNullOrWhiteSpace(code)) {
        return TokenIssuingResult.FromError("invalid_grant", "The code is missing.");
      }
      PendingCode pending;
      if (!_CodesByHash.TryRemove(CheapOAuthGrantStore.HashToken(code), out pending)) {
        return TokenIssuingResult.FromError("invalid_grant", "The code is invalid or was already used.");
      }
      if (pending.ExpiresUtc <= _UtcNow()) {
        return TokenIssuingResult.FromError("invalid_grant", "The code expired.");
      }
      if (!string.Equals(pending.ClientId, clientId, StringComparison.Ordinal)) {
        return TokenIssuingResult.FromError("invalid_grant", "The code was issued to another client.");
      }
      codeChallenge = pending.CodeChallenge;
      resource = pending.Resource;
      return this.IssueTokens(
        pending.ClientId, pending.Subject, pending.RetainedSecret, pending.Scopes, pending.Resource, CheapOAuthGrantStore.CreateRandomToken()
      );
    }

    #endregion

    #region " Refresh Token Flow "

    /// <summary>
    /// Rotates the refresh token: the presented token is consumed and a new pair is issued.
    /// Presenting an already consumed refresh token revokes the whole token family (reuse detection).
    /// </summary>
    public TokenIssuingResult CreateFollowUpToken(string refreshToken) {
      if (string.IsNullOrWhiteSpace(refreshToken)) {
        return TokenIssuingResult.FromError("invalid_grant", "The refresh token is missing.");
      }
      string hash = CheapOAuthGrantStore.HashToken(refreshToken);
      RefreshGrant grant;
      if (!_RefreshGrantsByHash.TryRemove(hash, out grant)) {
        string family;
        if (_ConsumedRefreshHashesToFamily.TryGetValue(hash, out family)) {
          this.RevokeFamily(family);
        }
        return TokenIssuingResult.FromError("invalid_grant", "The refresh token is invalid, expired or was already used.");
      }
      _ConsumedRefreshHashesToFamily[hash] = grant.FamilyId;
      if (grant.ExpiresUtc <= _UtcNow()) {
        this.Persist();
        return TokenIssuingResult.FromError("invalid_grant", "The refresh token expired.");
      }
      return this.IssueTokens(grant.ClientId, grant.Subject, grant.RetainedSecret, grant.Scopes, grant.Resource, grant.FamilyId);
    }

    #endregion

    #region " Unsupported Flows "

    /// <summary>
    /// The implicit flow is not supported (OAuth 2.1).
    /// </summary>
    public bool TryValidateSessionIdAndCreateToken(
      string apiClientId, string sessionId, string[] selectedScopes, out TokenIssuingResult tokenResult
    ) {
      tokenResult = TokenIssuingResult.FromError("unsupported_response_type", "Only the authorization code flow (with PKCE) is supported.");
      return false;
    }

    /// <summary>
    /// The client credentials flow is not supported (access always needs a user).
    /// </summary>
    public TokenIssuingResult ValidateClientAndCreateToken(string clientId, string clientSecret, string[] selectedScopes) {
      return TokenIssuingResult.FromError("unsupported_grant_type", "The client credentials flow is not supported.");
    }

    #endregion

    #region " Discovery (RFC 8414) + Client Registration (RFC 7591) "

    /// <summary>
    /// Authorization code flow with mandatory PKCE S256, refresh tokens, public clients only
    /// and dynamic client registration.
    /// </summary>
    public AuthorizationServerCapabilities GetAuthorizationServerCapabilities() {
      AuthorizationServerCapabilities capabilities = new AuthorizationServerCapabilities();
      capabilities.ResponseTypesSupported = new string[] { "code" };
      capabilities.GrantTypesSupported = new string[] { "authorization_code", "refresh_token" };
      capabilities.CodeChallengeMethodsSupported = new string[] { "S256" };
      capabilities.TokenEndpointAuthMethodsSupported = new string[] { "none" };
      capabilities.ScopesSupported = AccessTokenManager.ApplyApiPermissionPrefix(_Options.ScopesSupported);
      capabilities.SupportsDynamicClientRegistration = true;
      return capabilities;
    }

    /// <summary>
    /// Registers a public client (PKCE only) at the client registry.
    /// </summary>
    public bool TryRegisterClient(
      string clientName, string[] redirectUris, string tokenEndpointAuthMethod,
      out string clientId, out string error, out string errorDescription
    ) {
      clientId = null;
      if (!string.IsNullOrWhiteSpace(tokenEndpointAuthMethod) && !string.Equals(tokenEndpointAuthMethod, "none", StringComparison.Ordinal)) {
        error = "invalid_client_metadata";
        errorDescription = "Only public clients ('token_endpoint_auth_method' = 'none') are supported.";
        return false;
      }
      try {
        clientId = _ClientRegistry.RegisterClient(clientName, redirectUris);
      }
      catch (ArgumentException ex) {
        DevLogger.LogError(ex);
        error = "invalid_redirect_uri";
        errorDescription = ex.Message;
        return false;
      }
      catch (InvalidOperationException ex) {
        DevLogger.LogError(ex);
        error = "invalid_client_metadata";
        errorDescription = ex.Message;
        return false;
      }
      error = null;
      errorDescription = null;
      return true;
    }

    #endregion

    /// <summary>
    /// Validates the client and its redirect URI (exact match against the registration).
    /// </summary>
    public bool TryValidateApiClient(string apiClientId, string apiCallerHost, string redirectUri, out string message) {
      if (!_ClientRegistry.IsKnownClient(apiClientId)) {
        message = "Unknown client.";
        return false;
      }
      if (!_ClientRegistry.IsRegisteredRedirectUri(apiClientId, redirectUri, apiCallerHost)) {
        message = "The redirect URI is not registered for this client.";
        return false;
      }
      message = "Valid client";
      return true;
    }

    /// <summary>
    /// RFC 7662 introspection of access tokens issued by this service (never exposes the retained secret).
    /// The resource indicator of the grant is returned as claim 'aud'.
    /// </summary>
    public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {
      claims = new Dictionary<string, object>();
      CheapOAuthGrant grant;
      if (!_GrantStore.TryGetGrant(rawToken, out grant)) {
        isActive = false;
        return;
      }
      isActive = true;
      claims["sub"] = grant.Subject;
      claims["scope"] = string.Join(" ", grant.Scopes);
      claims["exp"] = new DateTimeOffset(DateTime.SpecifyKind(grant.ExpiresUtc, DateTimeKind.Utc)).ToUnixTimeSeconds();
      if (!string.IsNullOrWhiteSpace(grant.Resource)) {
        claims["aud"] = grant.Resource;
      }
    }

    private TokenIssuingResult IssueTokens(string clientId, string subject, string retainedSecret, string[] scopes, string resource, string familyId) {
      this.RemoveExpiredEntries();
      string accessToken = _GrantStore.IssueAccessToken(subject, retainedSecret, scopes, resource, _Options.AccessTokenLifetime);
      string refreshToken = CheapOAuthGrantStore.CreateRandomToken();
      _RefreshGrantsByHash[CheapOAuthGrantStore.HashToken(refreshToken)] = new RefreshGrant(
        clientId, subject, retainedSecret, scopes, resource, familyId, _UtcNow().Add(_Options.RefreshTokenLifetime)
      );
      this.Persist();
      TokenIssuingResult result = new TokenIssuingResult();
      result.access_token = accessToken;
      result.token_type = "Bearer";
      result.expires_in = (int)_Options.AccessTokenLifetime.TotalSeconds;
      result.refresh_token = refreshToken;
      result.scope = string.Join(" ", scopes);
      return result;
    }

    private void RevokeFamily(string familyId) {
      foreach (KeyValuePair<string, RefreshGrant> entry in _RefreshGrantsByHash) {
        if (string.Equals(entry.Value.FamilyId, familyId, StringComparison.Ordinal)) {
          RefreshGrant removed;
          if (_RefreshGrantsByHash.TryRemove(entry.Key, out removed)) {
            _GrantStore.RevokeAllAccessTokensOfSubject(removed.Subject);
          }
        }
      }
      this.Persist();
    }

    private bool TryGetSession(string clientId, string sessionId, bool consume, out LoginSession session) {
      session = null;
      if (string.IsNullOrWhiteSpace(sessionId)) {
        return false;
      }
      string hash = CheapOAuthGrantStore.HashToken(sessionId);
      LoginSession found;
      bool exists;
      if (consume) {
        exists = _SessionsByHash.TryRemove(hash, out found);
      }
      else {
        exists = _SessionsByHash.TryGetValue(hash, out found);
      }
      if (!exists || found.ExpiresUtc <= _UtcNow() || !string.Equals(found.ClientId, clientId, StringComparison.Ordinal)) {
        return false;
      }
      session = found;
      return true;
    }

    private void RemoveExpiredEntries() {
      DateTime now = _UtcNow();
      foreach (KeyValuePair<string, LoginSession> entry in _SessionsByHash) {
        if (entry.Value.ExpiresUtc <= now) {
          LoginSession removed;
          _SessionsByHash.TryRemove(entry.Key, out removed);
        }
      }
      foreach (KeyValuePair<string, PendingCode> entry in _CodesByHash) {
        if (entry.Value.ExpiresUtc <= now) {
          PendingCode removed;
          _CodesByHash.TryRemove(entry.Key, out removed);
        }
      }
      foreach (KeyValuePair<string, RefreshGrant> entry in _RefreshGrantsByHash) {
        if (entry.Value.ExpiresUtc <= now) {
          RefreshGrant removed;
          _RefreshGrantsByHash.TryRemove(entry.Key, out removed);
        }
      }
    }

    /// <summary>
    /// Returns the scopes of the user which were requested. If nothing was requested, either all scopes
    /// of the user ('allIfNoneRequested') or none are returned.
    /// </summary>
    private static string[] IntersectScopes(string[] userScopes, string[] requestedScopes, bool allIfNoneRequested) {
      if (userScopes == null) {
        return new string[] { };
      }
      if (requestedScopes == null || requestedScopes.Length == 0) {
        if (allIfNoneRequested) {
          return userScopes;
        }
        return new string[] { };
      }
      //requested scopes are accepted with or without the configured prefix
      string[] prefixedRequestedScopes = AccessTokenManager.ApplyApiPermissionPrefix(requestedScopes);
      return userScopes.Where(
        (userScope) => prefixedRequestedScopes.Contains(userScope, StringComparer.OrdinalIgnoreCase)
      ).ToArray();
    }

    #region " State Classes "

    private sealed class LoginSession {

      private readonly string _ClientId;
      private readonly string _Subject;
      private readonly string _RetainedSecret;
      private readonly string[] _Scopes;
      private readonly DateTime _ExpiresUtc;

      public LoginSession(string clientId, string subject, string retainedSecret, string[] scopes, DateTime expiresUtc) {
        _ClientId = clientId;
        _Subject = subject;
        _RetainedSecret = retainedSecret;
        _Scopes = scopes;
        _ExpiresUtc = expiresUtc;
      }

      public string ClientId {
        get {
          return _ClientId;
        }
      }

      public string Subject {
        get {
          return _Subject;
        }
      }

      public string RetainedSecret {
        get {
          return _RetainedSecret;
        }
      }

      public string[] Scopes {
        get {
          return _Scopes;
        }
      }

      public DateTime ExpiresUtc {
        get {
          return _ExpiresUtc;
        }
      }

    }

    private sealed class PendingCode {

      private readonly string _ClientId;
      private readonly string _Subject;
      private readonly string _RetainedSecret;
      private readonly string[] _Scopes;
      private readonly string _CodeChallenge;
      private readonly string _Resource;
      private readonly DateTime _ExpiresUtc;

      public PendingCode(string clientId, string subject, string retainedSecret, string[] scopes, string codeChallenge, string resource, DateTime expiresUtc) {
        _ClientId = clientId;
        _Subject = subject;
        _RetainedSecret = retainedSecret;
        _Scopes = scopes;
        _CodeChallenge = codeChallenge;
        _Resource = resource;
        _ExpiresUtc = expiresUtc;
      }

      public string ClientId {
        get {
          return _ClientId;
        }
      }

      public string Subject {
        get {
          return _Subject;
        }
      }

      public string RetainedSecret {
        get {
          return _RetainedSecret;
        }
      }

      public string[] Scopes {
        get {
          return _Scopes;
        }
      }

      public string CodeChallenge {
        get {
          return _CodeChallenge;
        }
      }

      public string Resource {
        get {
          return _Resource;
        }
      }

      public DateTime ExpiresUtc {
        get {
          return _ExpiresUtc;
        }
      }

    }

    private sealed class RefreshGrant {

      private readonly string _ClientId;
      private readonly string _Subject;
      private readonly string _RetainedSecret;
      private readonly string[] _Scopes;
      private readonly string _Resource;
      private readonly string _FamilyId;
      private readonly DateTime _ExpiresUtc;

      public RefreshGrant(string clientId, string subject, string retainedSecret, string[] scopes, string resource, string familyId, DateTime expiresUtc) {
        _ClientId = clientId;
        _Subject = subject;
        _RetainedSecret = retainedSecret;
        _Scopes = scopes;
        _Resource = resource;
        _FamilyId = familyId;
        _ExpiresUtc = expiresUtc;
      }

      public string ClientId {
        get {
          return _ClientId;
        }
      }

      public string Subject {
        get {
          return _Subject;
        }
      }

      public string RetainedSecret {
        get {
          return _RetainedSecret;
        }
      }

      public string[] Scopes {
        get {
          return _Scopes;
        }
      }

      public string Resource {
        get {
          return _Resource;
        }
      }

      public string FamilyId {
        get {
          return _FamilyId;
        }
      }

      public DateTime ExpiresUtc {
        get {
          return _ExpiresUtc;
        }
      }

    }

    #endregion

  }

}
