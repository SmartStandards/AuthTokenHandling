using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security {

  /// <summary>
  /// Tests for the 'Cheap OAuth Server' (ASP.NET Core only).
  /// </summary>
  [TestClass]
  public class CheapOAuthServerTests {

    private const string _RedirectUri = "https://claude.ai/api/mcp/auth_callback";
    private const string _Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private DateTime _Now;

    [TestInitialize]
    public void Initialize() {
      _Now = new DateTime(2025, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    }

    private CheapOAuthOptions CreateOptions() {
      CheapOAuthOptions options = new CheapOAuthOptions();
      options.UseFixedAccounts(
        ("alice", "secret", new string[] { "mcp" }),
        ("bob", "secret2", new string[] { "mcp", "admin" })
      );
      return options;
    }

    private CheapOAuthService CreateService(CheapOAuthOptions options) {
      Func<DateTime> clock = () => _Now;
      return new CheapOAuthService(
        options, new CheapOAuthGrantStore(clock), new CheapOAuthClientRegistry(options, clock), clock
      );
    }

    /// <summary>
    /// Runs login + consent and returns the one-time code.
    /// </summary>
    private string LoginAndCreateCode(CheapOAuthService service, string clientId, string user, string password, string[] scopes, string resource) {
      string sessionId;
      string message;
      Assert.IsTrue(service.TryAuthenticate(clientId, user, password, false, null, out sessionId, out message), message);
      string code;
      Assert.IsTrue(service.TryValidateSessionIdAndCreateRetrievalCode(clientId, sessionId, scopes, _Challenge, resource, out code, out message), message);
      return code;
    }

    [TestMethod]
    public void CodeFlow_ValidLogin_IssuesTokensWithScopesAndAudience() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient("Claude", new string[] { _RedirectUri });

      string message;
      Assert.IsTrue(service.TryValidateApiClient(clientId, "localhost", _RedirectUri, out message), message);

      string code = this.LoginAndCreateCode(service, clientId, "bob", "secret2", new string[] { "mcp", "foreign" }, "https://api.example/mcp");
      string codeChallenge;
      string resource;
      TokenIssuingResult result = service.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);

      Assert.IsFalse(string.IsNullOrWhiteSpace(result.access_token));
      Assert.IsFalse(string.IsNullOrWhiteSpace(result.refresh_token));
      Assert.AreEqual(_Challenge, codeChallenge);
      Assert.AreEqual("https://api.example/mcp", resource);
      Assert.AreEqual("API:mcp", result.scope, "granted scopes must be the (prefixed) intersection of user scopes and selected scopes");

      bool isActive;
      Dictionary<string, object> claims;
      service.IntrospectAccessToken(result.access_token, out isActive, out claims);
      Assert.IsTrue(isActive);
      Assert.AreEqual("bob", claims["sub"]);
      Assert.AreEqual("https://api.example/mcp", claims["aud"]);
    }

    [TestMethod]
    public void TryAuthenticate_InvalidPassword_Fails() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string sessionId;
      string message;
      Assert.IsFalse(service.TryAuthenticate(clientId, "alice", "wrong", false, null, out sessionId, out message));
      Assert.IsFalse(service.TryAuthenticate(clientId, "unknown", "secret", false, null, out sessionId, out message));
    }

    [TestMethod]
    public void TryAuthenticate_BackendUnavailable_Fails() {
      CheapOAuthOptions options = new CheapOAuthOptions();
      options.ValidateLogin = (user, password) => CheapOAuthLoginResult.BackendUnavailable();
      CheapOAuthService service = this.CreateService(options);
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string sessionId;
      string message;
      Assert.IsFalse(service.TryAuthenticate(clientId, "alice", "secret", false, null, out sessionId, out message));
      StringAssert.Contains(message, "not reachable");
    }

    [TestMethod]
    public void CreateRetrievalCode_WithoutPkce_Fails() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string sessionId;
      string message;
      Assert.IsTrue(service.TryAuthenticate(clientId, "alice", "secret", false, null, out sessionId, out message));
      string code;
      Assert.IsFalse(service.TryValidateSessionIdAndCreateRetrievalCode(clientId, sessionId, new string[] { "mcp" }, null, null, out code, out message));
    }

    [TestMethod]
    public void RetrieveTokenByCode_SecondUse_Fails() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string code = this.LoginAndCreateCode(service, clientId, "alice", "secret", new string[] { "mcp" }, null);
      string codeChallenge;
      string resource;
      TokenIssuingResult first = service.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);
      Assert.IsFalse(string.IsNullOrWhiteSpace(first.access_token));
      TokenIssuingResult second = service.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);
      Assert.IsTrue(string.IsNullOrWhiteSpace(second.access_token));
    }

    [TestMethod]
    public void RetrieveTokenByCode_OtherClient_Fails() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string otherClientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string code = this.LoginAndCreateCode(service, clientId, "alice", "secret", new string[] { "mcp" }, null);
      string codeChallenge;
      string resource;
      TokenIssuingResult result = service.RetrieveTokenByCode(otherClientId, null, code, out codeChallenge, out resource);
      Assert.IsTrue(string.IsNullOrWhiteSpace(result.access_token));
    }

    [TestMethod]
    public void RefreshToken_Reuse_RevokesFamilyAndAccessTokens() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string code = this.LoginAndCreateCode(service, clientId, "alice", "secret", new string[] { "mcp" }, null);
      string codeChallenge;
      string resource;
      TokenIssuingResult initial = service.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);

      TokenIssuingResult rotated = service.CreateFollowUpToken(initial.refresh_token);
      Assert.IsFalse(string.IsNullOrWhiteSpace(rotated.access_token));
      Assert.AreNotEqual(initial.refresh_token, rotated.refresh_token);

      TokenIssuingResult reused = service.CreateFollowUpToken(initial.refresh_token);
      Assert.IsTrue(string.IsNullOrWhiteSpace(reused.access_token));

      TokenIssuingResult afterRevocation = service.CreateFollowUpToken(rotated.refresh_token);
      Assert.IsTrue(string.IsNullOrWhiteSpace(afterRevocation.access_token), "the whole family must be revoked");

      bool isActive;
      Dictionary<string, object> claims;
      service.IntrospectAccessToken(rotated.access_token, out isActive, out claims);
      Assert.IsFalse(isActive, "access tokens of the subject must be revoked");
    }

    [TestMethod]
    public void AccessToken_AfterLifetime_IsInactive() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string code = this.LoginAndCreateCode(service, clientId, "alice", "secret", new string[] { "mcp" }, null);
      string codeChallenge;
      string resource;
      TokenIssuingResult result = service.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);
      _Now = _Now.AddMinutes(16);
      bool isActive;
      Dictionary<string, object> claims;
      service.IntrospectAccessToken(result.access_token, out isActive, out claims);
      Assert.IsFalse(isActive);
    }

    [TestMethod]
    public void RetainedSecret_IsKeptInGrantButNotExposed() {
      CheapOAuthOptions options = new CheapOAuthOptions();
      options.ValidateLogin = (user, password) => CheapOAuthLoginResult.Valid(new string[] { "mcp" }, password);
      CheapOAuthService service = this.CreateService(options);
      string clientId = service.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
      string code = this.LoginAndCreateCode(service, clientId, "carol", "caldav-pw", new string[] { "mcp" }, null);
      string codeChallenge;
      string resource;
      TokenIssuingResult result = service.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);

      CheapOAuthGrant grant;
      Assert.IsTrue(service.GrantStore.TryGetGrant("Bearer " + result.access_token, out grant));
      Assert.AreEqual("caldav-pw", grant.RetainedSecret);

      bool isActive;
      Dictionary<string, object> claims;
      service.IntrospectAccessToken(result.access_token, out isActive, out claims);
      foreach (object value in claims.Values) {
        Assert.AreNotEqual("caldav-pw", value);
      }
    }

    [TestMethod]
    public void ClientRegistry_Restrictions_AreEnforced() {
      CheapOAuthOptions options = this.CreateOptions();
      options.AllowedRedirectHosts = new string[] { "claude.ai" };
      options.MaxClientRegistrations = 1;
      Func<DateTime> clock = () => _Now;
      CheapOAuthClientRegistry registry = new CheapOAuthClientRegistry(options, clock);

      Assert.ThrowsException<ArgumentException>(() => registry.RegisterClient(null, new string[] { "https://evil.example/cb" }));
      Assert.ThrowsException<ArgumentException>(() => registry.RegisterClient(null, new string[] { "http://claude.ai/cb" }));
      string clientId = registry.RegisterClient("Claude", new string[] { _RedirectUri });
      Assert.ThrowsException<InvalidOperationException>(() => registry.RegisterClient(null, new string[] { _RedirectUri }));

      Assert.IsTrue(registry.IsRegisteredRedirectUri(clientId, _RedirectUri, "localhost"));
      Assert.IsFalse(registry.IsRegisteredRedirectUri(clientId, _RedirectUri + "x", "localhost"));
      Assert.AreEqual("Claude", registry.GetClientName(clientId));

      _Now = _Now.AddDays(31);
      Assert.IsFalse(registry.IsKnownClient(clientId), "unused registrations must expire");
    }

    [TestMethod]
    public void ClientRegistry_SwaggerClient_RequiresRequestHostAndPath() {
      CheapOAuthClientRegistry registry = new CheapOAuthClientRegistry(this.CreateOptions());
      Assert.IsTrue(registry.IsKnownClient(CheapOAuthOptions.SwaggerClientId));
      Assert.IsTrue(registry.IsRegisteredRedirectUri("swagger-ui", "https://myhost/docs/oauth2-redirect.html", "myhost"));
      Assert.IsFalse(registry.IsRegisteredRedirectUri("swagger-ui", "https://evil/docs/oauth2-redirect.html", "myhost"));
      Assert.IsFalse(registry.IsRegisteredRedirectUri("swagger-ui", "https://myhost/other.html", "myhost"));

      CheapOAuthOptions disabled = this.CreateOptions();
      disabled.SwaggerRedirectPath = null;
      Assert.IsFalse(new CheapOAuthClientRegistry(disabled).IsKnownClient(CheapOAuthOptions.SwaggerClientId));
    }

    [TestMethod]
    public void Persistence_RestoresClientsAndGrants_AndIsEncrypted() {
      string directory = Path.Combine(Path.GetTempPath(), "CheapOAuthTest_" + Guid.NewGuid().ToString("N"));
      try {
        CheapOAuthOptions options = new CheapOAuthOptions();
        options.ValidateLogin = (user, password) => CheapOAuthLoginResult.Valid(new string[] { "mcp" }, "very-secret-value");

        CheapOAuthService first = this.CreatePersistentService(options, directory);
        string clientId = first.ClientRegistry.RegisterClient(null, new string[] { _RedirectUri });
        string code = this.LoginAndCreateCode(first, clientId, "alice", "pw", new string[] { "mcp" }, null);
        string codeChallenge;
        string resource;
        TokenIssuingResult result = first.RetrieveTokenByCode(clientId, null, code, out codeChallenge, out resource);

        string fileContent = File.ReadAllText(Path.Combine(directory, "cheap-oauth-state.protected"));
        Assert.IsFalse(fileContent.Contains("very-secret-value"), "the state must be encrypted");
        Assert.IsFalse(fileContent.Contains(result.access_token), "raw tokens must never be stored");

        CheapOAuthService second = this.CreatePersistentService(options, directory);
        Assert.IsTrue(second.ClientRegistry.IsKnownClient(clientId));
        bool isActive;
        Dictionary<string, object> claims;
        second.IntrospectAccessToken(result.access_token, out isActive, out claims);
        Assert.IsTrue(isActive);
        TokenIssuingResult refreshed = second.CreateFollowUpToken(result.refresh_token);
        Assert.IsFalse(string.IsNullOrWhiteSpace(refreshed.access_token));
      }
      finally {
        if (Directory.Exists(directory)) {
          Directory.Delete(directory, true);
        }
      }
    }

    [TestMethod]
    public void IntrospectorFactory_InProcessEndpoint_ResolvesToService() {
      CheapOAuthService service = this.CreateService(this.CreateOptions());
      string endpointUrl = "{RequestBaseUrl}/oauth2/introspect";
      IntrospectorFactory.RegisterInProcessIntrospector(endpointUrl, service);
      try {
        AuthTokenConfig config = new AuthTokenConfig();
        config.ValidationMode = WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT;
        config.ValidationEndpointUrl = endpointUrl;
        Assert.AreSame(service, IntrospectorFactory.CreateFromConfig(config));

        config.ValidationEndpointUrl = "https://other/oauth2/introspect";
        Assert.AreNotSame(service, IntrospectorFactory.CreateFromConfig(config));
      }
      finally {
        IntrospectorFactory.RegisterInProcessIntrospector(endpointUrl, null);
      }
    }

    private CheapOAuthService CreatePersistentService(CheapOAuthOptions options, string directory) {
      Func<DateTime> clock = () => _Now;
      CheapOAuthStatePersistence persistence = new CheapOAuthStatePersistence(directory, null);
      CheapOAuthGrantStore grantStore = new CheapOAuthGrantStore(clock);
      CheapOAuthClientRegistry registry = new CheapOAuthClientRegistry(options, clock);
      CheapOAuthService service = new CheapOAuthService(options, grantStore, registry, clock);
      registry.AttachPersistence(persistence);
      grantStore.AttachPersistence(persistence);
      service.AttachPersistence(persistence);
      return service;
    }

  }

}
