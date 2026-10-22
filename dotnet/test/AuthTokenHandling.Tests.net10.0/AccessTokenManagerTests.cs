using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;

namespace Security {

  /// <summary>
  /// Acceptance tests for the AccessTokenManager (resolution, requirements, composite introspection, register,
  /// issuer routing, relay control, persistence and challenge behavior).
  /// </summary>
  [TestClass]
  [DoNotParallelize]
  public class AccessTokenManagerTests {

    #region " Test doubles "

    /// <summary>
    /// Introspector which accepts exactly one token (or throws, if configured).
    /// </summary>
    private class FakeIntrospector : IAccessTokenIntrospector {

      private string _AcceptedToken;
      private string _Subject;
      private string _Scopes;
      private bool _Throw;
      private int _CallCount;

      public FakeIntrospector(string acceptedToken, string subject, string scopes, bool throwException = false) {
        _AcceptedToken = acceptedToken;
        _Subject = subject;
        _Scopes = scopes;
        _Throw = throwException;
      }

      public int CallCount {
        get {
          return _CallCount;
        }
      }

      public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {
        _CallCount++;
        if (_Throw) {
          throw new InvalidOperationException("technical failure");
        }
        claims = new Dictionary<string, object>();
        isActive = (rawToken == _AcceptedToken);
        if (isActive) {
          claims["sub"] = _Subject;
          claims["scope"] = _Scopes;
        }
      }

    }

    /// <summary>
    /// Issuer which always returns the same token.
    /// </summary>
    private class FakeIssuer : IAccessTokenIssuer {

      private string _Token;

      public FakeIssuer(string token) {
        _Token = token;
      }

      public bool TryRequestAccessToken(out TokenIssuingResult result) {
        result = new TokenIssuingResult();
        result.access_token = _Token;
        result.expires_in = 3600;
        return true;
      }

      public bool TryRequestAccessToken(Dictionary<string, object> claimsToRequest, out TokenIssuingResult result) {
        return this.TryRequestAccessToken(out result);
      }

    }

    /// <summary>
    /// In-memory persistence which records every save.
    /// </summary>
    private class FakePersistence : ITokenPersistenceProvider {

      private Dictionary<string, PersistedTokenSet> _Store = new Dictionary<string, PersistedTokenSet>();

      public Dictionary<string, PersistedTokenSet> Store {
        get {
          return _Store;
        }
      }

      private static string BuildKey(string tokenSourceId, bool userScope, string customScope) {
        return tokenSourceId + "|" + userScope.ToString() + "|" + customScope;
      }

      public bool TryLoadTokens(string tokenSourceId, bool userScope, string customScope, out PersistedTokenSet tokens) {
        return _Store.TryGetValue(BuildKey(tokenSourceId, userScope, customScope), out tokens);
      }

      public void SaveTokens(string tokenSourceId, bool userScope, string customScope, PersistedTokenSet tokens) {
        _Store[BuildKey(tokenSourceId, userScope, customScope)] = tokens;
      }

      public void DeleteTokens(string tokenSourceId, bool userScope, string customScope) {
        _Store.Remove(BuildKey(tokenSourceId, userScope, customScope));
      }

    }

    /// <summary>
    /// Local copy of UJMW's 'AuthHeaderValidationMethod' delegate (compile test without UJMW reference).
    /// </summary>
    private delegate bool AuthHeaderValidationMethod(
      string rawAuthHeader,
      Type contractType,
      MethodInfo targetContractMethod,
      string apiGroupName,
      string callingMachine,
      ref int httpReturnCode,
      ref string failedReason,
      ref KeyValuePair<string, string>[] responseHeaders
    );

    public interface IDemoContract {
    }

    [AuthTokenSource(null)]
    public interface IAnonymousContract {
    }

    #endregion

    #region " Setup "

    [TestInitialize]
    public void Initialize() {
      AccessTokenManager.Reset();
      AccessTokenValidator.ClearChallengeHeaders();
      AccessTokenValidator.ConfigureTokenValidationViaAccessTokenManager((c) => {
        c.ChangeCachingLifetime(0);
        c.ChangeScopePrefixForApiPermissions("API:");
        c.EnableAnonymousSubject(null);
        c.UseScopeVisitor(null);
        c.UseRawTokenExposal(null);
        c.UseAuditingHook(null);
      });
    }

    [TestCleanup]
    public void Cleanup() {
      AccessTokenManager.Reset();
      AccessTokenValidator.ClearChallengeHeaders();
      AccessTokenValidator.ConfigureTokenValidationViaAccessTokenManager((c) => {
        c.ChangeScopePrefixForApiPermissions("API:");
      });
    }

    private static void Register(string tokenSourceId, IAccessTokenIntrospector introspector, IAccessTokenIssuer issuer = null) {
      AccessTokenManager.ConfigureTokenSupply((c) => {
        c.ApplyCustomTokenSource(tokenSourceId, issuer, introspector);
      });
    }

    private static bool Validate(string token, Type contractType, string apiGroupName, out int httpReturnCode, out KeyValuePair<string, string>[] headers) {
      int code = 200;
      string reason = string.Empty;
      KeyValuePair<string, string>[] responseHeaders = new KeyValuePair<string, string>[] { };
      bool result = AccessTokenValidator.TryValidateHttpAuthHeader(
        token, contractType, null, apiGroupName, "localhost", ref code, ref reason, ref responseHeaders
      );
      httpReturnCode = code;
      headers = responseHeaders;
      return result;
    }

    #endregion

    #region " Resolution "

    [TestMethod]
    public void ResolveTokenSourceIds_WithoutMapping_ReturnsLogicalName() {
      CollectionAssert.AreEqual(new string[] { "GroupA" }, AccessTokenManager.ResolveTokenSourceIds("GroupA"));
    }

    [TestMethod]
    public void ResolveTokenSourceIds_WithMapping_ReturnsTargetsInOrder() {
      AccessTokenManager.MapTokenSourceId("src1", "GroupA");
      AccessTokenManager.MapTokenSourceId("src2", "GroupA");
      CollectionAssert.AreEqual(new string[] { "src1", "src2" }, AccessTokenManager.ResolveTokenSourceIds("GroupA"));
    }

    [TestMethod]
    public void ResolveTokenSourceIds_EmptyNullAndZeroGuid_ResolveToDefault() {
      CollectionAssert.AreEqual(new string[] { "default" }, AccessTokenManager.ResolveTokenSourceIds(string.Empty));
      CollectionAssert.AreEqual(new string[] { "default" }, AccessTokenManager.ResolveTokenSourceIds(null));
      CollectionAssert.AreEqual(new string[] { "default" }, AccessTokenManager.ResolveTokenSourceIds(AccessTokenManager.LegacyDefaultTokenSourceId));
    }

    [TestMethod]
    public void SetDefaultTokenSourceId_MapsDefault() {
      AccessTokenManager.SetDefaultTokenSourceId("main");
      CollectionAssert.AreEqual(new string[] { "main" }, AccessTokenManager.ResolveTokenSourceIds(string.Empty));
    }

    [TestMethod]
    public void ResolveRegisteredChain_FirstRegisteredWins_ElseDefault_ElseFailClosed() {
      Register("src2", new FakeIntrospector("t", "s", ""));
      Register("default", new FakeIntrospector("t", "s", ""));
      CollectionAssert.AreEqual(new string[] { "src2" }, AccessTokenManager.ResolveRegisteredTokenSourceIdsForChain(new string[] { "unknown", "src2" }));
      CollectionAssert.AreEqual(new string[] { "default" }, AccessTokenManager.ResolveRegisteredTokenSourceIdsForChain(new string[] { "unknown" }));

      AccessTokenManager.Reset();
      Assert.AreEqual(0, AccessTokenManager.ResolveRegisteredTokenSourceIdsForChain(new string[] { "unknown" }).Length);
    }

    #endregion

    #region " Anonymous / scopes "

    [TestMethod]
    public void MapAnonymous_AnyLogicalNameAnonymous_NoTokenRequired() {
      Register("default", new FakeIntrospector("t", "s", ""));
      AccessTokenManager.MapAnonymous("PublicGroup");
      AccessTokenManager.RequireScope("mcp");

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsTrue(Validate(null, typeof(IDemoContract), "PublicGroup", out code, out headers));
      Assert.IsFalse(Validate(null, typeof(IDemoContract), "OtherGroup", out code, out headers), "fail closed");
      Assert.AreEqual(401, code);
    }

    [TestMethod]
    public void AuthTokenSourceAttributeNull_IsAnonymous() {
      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsTrue(Validate(null, typeof(IAnonymousContract), string.Empty, out code, out headers));
    }

    [TestMethod]
    public void RequireScope_ApiPrefix_AppliedOnce() {
      AccessTokenManager.RequireScope("mcp");
      AccessTokenManager.RequireScope("API:admin", "GroupA");
      CollectionAssert.AreEquivalent(new string[] { "API:mcp", "API:admin" }, AccessTokenManager.GetRequiredScopes("GroupA"));
      CollectionAssert.AreEquivalent(new string[] { "API:mcp" }, AccessTokenManager.GetRequiredScopes("GroupB"));
    }

    [TestMethod]
    public void RequireScope_AblPrefix_AppliedAndEnforced() {
      AccessTokenValidator.ConfigureTokenValidationViaAccessTokenManager((c) => {
        c.ChangeCachingLifetime(0);
        c.ChangeScopePrefixForApiPermissions("ABL:");
      });
      Register("default", new FakeIntrospector("tok", "alice", "ABL:mcp"));
      AccessTokenManager.RequireScope("mcp");
      CollectionAssert.AreEqual(new string[] { "ABL:mcp" }, AccessTokenManager.GetRequiredScopes());

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsTrue(Validate("Bearer tok", typeof(IDemoContract), string.Empty, out code, out headers));

      AccessTokenManager.RequireScope("admin", "GroupA");
      Assert.IsFalse(Validate("Bearer tok", typeof(IDemoContract), "GroupA", out code, out headers));
      Assert.AreEqual(403, code);
    }

    [TestMethod]
    public void RequireScope_WithoutPrefix_EscapeHatch() {
      AccessTokenManager.RequireScope("openid", null, false);
      AccessTokenManager.RequireScope("mcp", null, true);
      CollectionAssert.AreEquivalent(new string[] { "openid", "API:mcp" }, AccessTokenManager.GetRequiredScopes());

      Register("default", new FakeIntrospector("tok", "alice", "openid API:mcp"));
      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsTrue(Validate("Bearer tok", typeof(IDemoContract), string.Empty, out code, out headers));
    }

    #endregion

    #region " Composite introspector / register "

    [TestMethod]
    public void CompositeIntrospector_TriesInOrder_AndPushesUnderMatchingSource() {
      FakeIntrospector first = new FakeIntrospector("other", "x", "");
      FakeIntrospector second = new FakeIntrospector("tok", "bob", "API:read");
      Register("src1", first);
      Register("src2", second);
      AccessTokenManager.MapTokenSourceId("src1", "GroupA");
      AccessTokenManager.MapTokenSourceId("src2", "GroupA");

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsTrue(Validate("Bearer tok", typeof(IDemoContract), "GroupA", out code, out headers));
      Assert.AreEqual(1, first.CallCount);
      Assert.AreEqual(1, second.CallCount);

      Assert.AreEqual("tok", AccessTokenManager.GetCurrentAccessToken("src2"));
      Assert.AreEqual("bob", AccessTokenManager.GetCurrentSubject("src2"));
      CollectionAssert.AreEqual(new string[] { "API:read" }, AccessTokenManager.GetCurrentScopes("src2"));
      Assert.IsFalse(AccessTokenManager.HasCurrentAccessToken("src1"));
    }

    [TestMethod]
    public void CompositeIntrospector_NoneActive_FailClosed() {
      Register("src1", new FakeIntrospector("a", "x", ""));
      Register("src2", new FakeIntrospector("b", "y", ""));
      AccessTokenManager.MapTokenSourceId("src1", "GroupA");
      AccessTokenManager.MapTokenSourceId("src2", "GroupA");

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsFalse(Validate("Bearer c", typeof(IDemoContract), "GroupA", out code, out headers));
    }

    [TestMethod]
    public void CompositeIntrospector_TechnicalFailure_NotCached() {
      AccessTokenValidator.ConfigureTokenValidationViaAccessTokenManager((c) => {
        c.ChangeCachingLifetime(10);
        c.ChangeScopePrefixForApiPermissions("API:");
      });
      FakeIntrospector failing = new FakeIntrospector("tok", "x", "", true);
      Register("src1", failing);
      Register("src2", new FakeIntrospector("other", "y", ""));
      AccessTokenManager.MapTokenSourceId("src1", "GroupNc");
      AccessTokenManager.MapTokenSourceId("src2", "GroupNc");

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsFalse(Validate("Bearer tok-nc", typeof(IDemoContract), "GroupNc", out code, out headers));
      Assert.IsFalse(Validate("Bearer tok-nc", typeof(IDemoContract), "GroupNc", out code, out headers));
      Assert.AreEqual(2, failing.CallCount, "a technical failure must not be cached");
    }

    [TestMethod]
    public void SetCurrentToken_UsesIntrospectorOnly_InactiveThrows_EmptyClears() {
      FakeIntrospector introspector = new FakeIntrospector("tok", "carol", "API:a API:b");
      Register("ui", introspector);
      int auditCount = 0;
      AccessTokenValidator.ConfigureTokenValidationViaAccessTokenManager((c) => {
        c.ChangeCachingLifetime(0);
        c.UseAuditingHook((m, cm, o, s, p, r, f, d) => { auditCount++; });
      });

      AccessTokenManager.SetCurrentToken("ui", "tok", "refresh", "id");
      Assert.AreEqual(1, introspector.CallCount);
      Assert.AreEqual(0, auditCount, "no auditing");
      Assert.AreEqual("tok", AccessTokenManager.GetCurrentAccessToken("ui"));
      Assert.AreEqual("refresh", AccessTokenManager.GetCurrentRefreshToken("ui"));
      Assert.AreEqual("id", AccessTokenManager.GetCurrentIdToken("ui"));
      Assert.AreEqual("carol", AccessTokenManager.GetCurrentSubject("ui"));
      CollectionAssert.AreEqual(new string[] { "API:a", "API:b" }, AccessTokenManager.GetCurrentScopes("ui"));

      Assert.ThrowsException<ArgumentException>(() => AccessTokenManager.SetCurrentToken("ui", "invalid"));

      AccessTokenManager.SetCurrentToken("ui", string.Empty);
      Assert.IsFalse(AccessTokenManager.HasCurrentAccessToken("ui"));
      Assert.AreEqual(string.Empty, AccessTokenManager.GetCurrentSubject("ui"));
      Assert.AreEqual(0, AccessTokenManager.GetCurrentScopes("ui").Length);
    }

    #endregion

    #region " Issuer routing / relay "

    [TestMethod]
    public void MapIssuer_RoutesBeforeChain_UnmappedFallsThrough() {
      Register("legacyGen", new FakeIntrospector("t", "s", ""));
      Register("default", new FakeIntrospector("t", "s", ""));
      AccessTokenManager.MapIssuer("legacyGen", "https://old-issuer");

      CompositeAccessTokenIntrospector routed = (CompositeAccessTokenIntrospector)AccessTokenManager.LookupForIntrospector(
        string.Empty, typeof(IDemoContract), null, "localhost", () => "HTTPS://OLD-ISSUER"
      );
      CollectionAssert.AreEqual(new string[] { "legacyGen" }, routed.TokenSourceIds);

      CompositeAccessTokenIntrospector fallThrough = (CompositeAccessTokenIntrospector)AccessTokenManager.LookupForIntrospector(
        string.Empty, typeof(IDemoContract), null, "localhost", () => "https://unknown"
      );
      CollectionAssert.AreEqual(new string[] { "default" }, fallThrough.TokenSourceIds);
    }

    [TestMethod]
    public void DisableTokenRelay_SuppressesPushAndOutgoingRelay() {
      Register("onDemand", new FakeIntrospector("tok", "s", ""), new FakeIssuer("issued"));
      AccessTokenManager.ConfigureTokenSupply((c) => {
        c.DisableTokenRelay("onDemand");
      });

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsTrue(Validate("Bearer tok", typeof(IDemoContract), "onDemand", out code, out headers));
      Assert.IsFalse(AccessTokenManager.HasCurrentAccessToken("onDemand"));

      string accessToken;
      Assert.IsFalse(AccessTokenManager.TryGetActiveTokenForTokenSource("onDemand", false, out accessToken));
    }

    #endregion

    #region " Persistence "

    [TestMethod]
    public void Persistence_OnlyOnOptIn() {
      FakePersistence persistence = new FakePersistence();
      Register("src1", null, new FakeIssuer("issued1"));
      Register("src2", null, new FakeIssuer("issued2"));
      AccessTokenManager.ConfigureTokenSupply((c) => {
        c.EnableAuthTokenPersistence("src2", true, null, persistence);
      });

      string accessToken;
      Assert.IsTrue(AccessTokenManager.TryGetActiveTokenForTokenSource("src1", false, out accessToken));
      Assert.AreEqual(0, persistence.Store.Count, "no persistence without opt-in");

      Assert.IsTrue(AccessTokenManager.TryGetActiveTokenForTokenSource("src2", false, out accessToken));
      Assert.AreEqual(1, persistence.Store.Count);
      Assert.AreEqual("issued2", persistence.Store.Values.Single().AccessToken);
    }

    [TestMethod]
    public void Persistence_IsolatedPerCustomScope_EmptyScopeSkipped() {
      FakePersistence persistence = new FakePersistence();
      string currentScope = "tenantA";
      Register("src", null, new FakeIssuer("issued"));
      AccessTokenManager.ConfigureTokenSupply((c) => {
        c.EnableAuthTokenPersistence("src", true, () => currentScope, persistence);
      });

      string accessToken;
      Assert.IsTrue(AccessTokenManager.TryGetActiveTokenForTokenSource("src", false, out accessToken));
      currentScope = "tenantB";
      Assert.IsTrue(AccessTokenManager.TryGetActiveTokenForTokenSource("src", true, out accessToken));
      Assert.AreEqual(2, persistence.Store.Count, "one record per isolation scope");

      currentScope = null;
      Assert.IsTrue(AccessTokenManager.TryGetActiveTokenForTokenSource("src", true, out accessToken));
      Assert.AreEqual(2, persistence.Store.Count, "no persistence without isolation scope");
    }

    #endregion

    #region " Challenge / delegate "

    [TestMethod]
    public void Challenge_On401_NotOn403_WithPrefixedScopes() {
      string[] seenScopes = null;
      int builderCalls = 0;
      AccessTokenValidator.ConfigureChallengeHeaders((statusCode, requiredScopes) => {
        builderCalls++;
        Assert.AreEqual(401, statusCode, "the challenge builder must only be invoked for 401");
        seenScopes = requiredScopes;
        return new KeyValuePair<string, string>[] { new KeyValuePair<string, string>("WWW-Authenticate", "Bearer") };
      });
      Register("default", new FakeIntrospector("tok", "alice", "API:other"));
      AccessTokenManager.RequireScope("mcp");

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsFalse(Validate(null, typeof(IDemoContract), string.Empty, out code, out headers));
      Assert.AreEqual(401, code);
      Assert.IsTrue(headers.Any((h) => h.Key == "WWW-Authenticate"));
      Assert.IsNotNull(seenScopes);
      CollectionAssert.Contains(seenScopes, "API:mcp");

      Assert.IsFalse(Validate("Bearer tok", typeof(IDemoContract), string.Empty, out code, out headers));
      Assert.AreEqual(403, code);
      Assert.IsFalse(headers.Any((h) => h.Key == "WWW-Authenticate"));
      Assert.AreEqual(1, builderCalls, "no challenge builder invocation for 403");
    }

    [TestMethod]
    public void Challenge_On401_ForInactiveToken() {
      int builderCalls = 0;
      AccessTokenValidator.ConfigureChallengeHeaders((statusCode, scopes) => {
        builderCalls++;
        return new KeyValuePair<string, string>[] { new KeyValuePair<string, string>("WWW-Authenticate", "Bearer") };
      });
      Register("default", new FakeIntrospector("tok", "alice", "API:mcp"));
      AccessTokenManager.RequireScope("mcp");

      int code;
      KeyValuePair<string, string>[] headers;
      Assert.IsFalse(Validate("Bearer expiredOrRevokedTok", typeof(IDemoContract), string.Empty, out code, out headers));
      Assert.AreEqual(401, code, "an inactive (e.g. expired) token must trigger re-authentication");
      Assert.IsTrue(headers.Any((h) => h.Key == "WWW-Authenticate"));
      Assert.AreEqual(1, builderCalls);
    }

    [TestMethod]
    public void TryValidateHttpAuthHeader_IsAssignableToUjmwDelegate() {
      AuthHeaderValidationMethod method = AccessTokenValidator.TryValidateHttpAuthHeader;
      Assert.IsNotNull(method);
    }

    #endregion

  }

}
