using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security {

  /// <summary>
  /// Tests for the PKCE (RFC 7636) support of the built-in OAuth server (ASP.NET Core only).
  /// </summary>
  [TestClass]
  public class PkceTests {

    // Test vector from RFC 7636 Appendix B
    private const string _RfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string _RfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #region " Helper-Level "

    /// <summary>
    /// Verifies the S256 computation against the RFC 7636 test vector.
    /// </summary>
    [TestMethod]
    public void ComputeS256Challenge_RfcTestVector_MatchesExpectedChallenge() {
      string challenge = OAuth2Controller.ComputeS256Challenge(_RfcVerifier);
      Assert.AreEqual(_RfcChallenge, challenge);
    }

    /// <summary>
    /// Verifies the validation of the authorize request params.
    /// </summary>
    [TestMethod]
    public void TryValidatePkceRequest_VariousInputs_EvaluatedCorrectly() {
      string error;

      Assert.IsTrue(OAuth2Controller.TryValidatePkceRequest(null, null, out error), "PKCE must be optional");
      Assert.IsNull(error);

      Assert.IsTrue(OAuth2Controller.TryValidatePkceRequest(_RfcChallenge, "S256", out error));
      Assert.IsNull(error);

      Assert.IsFalse(OAuth2Controller.TryValidatePkceRequest(_RfcChallenge, "plain", out error), "'plain' is not supported");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryValidatePkceRequest(_RfcChallenge, null, out error), "missing method means 'plain'");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryValidatePkceRequest(null, "S256", out error), "method without challenge");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryValidatePkceRequest("tooShort", "S256", out error));
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryValidatePkceRequest(_RfcChallenge.Substring(1) + "+", "S256", out error), "no BASE64URL");
      Assert.IsNotNull(error);
    }

    /// <summary>
    /// Verifies the code_verifier check for all relevant combinations.
    /// </summary>
    [TestMethod]
    public void TryVerifyPkce_VariousInputs_EvaluatedCorrectly() {
      string error;

      Assert.IsTrue(OAuth2Controller.TryVerifyPkce(null, null, out error), "no PKCE at all");
      Assert.IsNull(error);

      Assert.IsTrue(OAuth2Controller.TryVerifyPkce(_RfcChallenge, _RfcVerifier, out error));
      Assert.IsNull(error);

      Assert.IsFalse(OAuth2Controller.TryVerifyPkce(_RfcChallenge, null, out error), "missing verifier");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryVerifyPkce(null, _RfcVerifier, out error), "downgrade: verifier without challenge");
      Assert.IsNotNull(error);

      string otherVerifier = new string('a', 43);
      Assert.IsFalse(OAuth2Controller.TryVerifyPkce(_RfcChallenge, otherVerifier, out error), "mismatch");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryVerifyPkce(_RfcChallenge, "short", out error), "verifier too short");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryVerifyPkce(_RfcChallenge, new string('a', 129), out error), "verifier too long");
      Assert.IsNotNull(error);

      Assert.IsFalse(OAuth2Controller.TryVerifyPkce(_RfcChallenge, _RfcVerifier.Substring(1) + "!", out error), "invalid char");
      Assert.IsNotNull(error);
    }

    /// <summary>
    /// Verifies that the code challenge is injected into html forms (and is not lost silently).
    /// </summary>
    [TestMethod]
    public void TryInjectPkceFormField_VariousTemplates_EvaluatedCorrectly() {

      string html = "<body><form method=\"post\"><input name=\"x\"></form></body>";
      Assert.IsTrue(OAuth2Controller.TryInjectPkceFormField(ref html, _RfcChallenge));
      Assert.IsTrue(html.Contains($"name=\"codeChallenge\" value=\"{_RfcChallenge}\"></form>"));

      string unchanged = "<body><form></form></body>";
      Assert.IsTrue(OAuth2Controller.TryInjectPkceFormField(ref unchanged, null), "nothing to inject without PKCE");
      Assert.AreEqual("<body><form></form></body>", unchanged);

      string noForm = "<body>custom page</body>";
      Assert.IsFalse(OAuth2Controller.TryInjectPkceFormField(ref noForm, _RfcChallenge), "challenge must not get lost");
    }

    /// <summary>
    /// Verifies that the PKCE params are kept when redirecting back to the authorize page.
    /// </summary>
    [TestMethod]
    public void AppendPkceQueryParams_WithAndWithoutChallenge_EvaluatedCorrectly() {
      string url = "./authorize?client_id=abc";

      Assert.AreEqual(url, OAuth2Controller.AppendPkceQueryParams(url, null));
      Assert.AreEqual(
        url + "&code_challenge=" + _RfcChallenge + "&code_challenge_method=S256",
        OAuth2Controller.AppendPkceQueryParams(url, _RfcChallenge)
      );
    }

    #endregion

    #region " Token-Endpoint-Level "

    /// <summary>
    /// A code issued with challenge can be redeemed with the matching verifier.
    /// </summary>
    [TestMethod]
    public void RetrieveToken_ChallengeAndMatchingVerifier_ReturnsToken() {
      FakePkceOAuthService service = new FakePkceOAuthService();
      OAuth2Controller controller = CreateController(service);
      string code = service.StageCode(_RfcChallenge);

      TokenIssuingResult result = controller.RetrieveToken(CreateCodeRequest(code, _RfcVerifier));

      Assert.IsTrue(string.IsNullOrWhiteSpace(result.error), result.error_description);
      Assert.AreEqual(FakePkceOAuthService.IssuedAccessToken, result.access_token);
    }

    /// <summary>
    /// A wrong verifier is rejected and the code is consumed (no second try).
    /// </summary>
    [TestMethod]
    public void RetrieveToken_ChallengeAndWrongVerifier_ReturnsInvalidGrantAndConsumesCode() {
      FakePkceOAuthService service = new FakePkceOAuthService();
      OAuth2Controller controller = CreateController(service);
      string code = service.StageCode(_RfcChallenge);

      TokenIssuingResult result = controller.RetrieveToken(CreateCodeRequest(code, new string('a', 43)));

      Assert.AreEqual("invalid_grant", result.error);
      Assert.IsNull(result.access_token);

      TokenIssuingResult retry = controller.RetrieveToken(CreateCodeRequest(code, _RfcVerifier));
      Assert.IsFalse(string.IsNullOrWhiteSpace(retry.error), "the code must not be usable a second time");
      Assert.IsNull(retry.access_token);
    }

    /// <summary>
    /// A code issued with challenge cannot be redeemed without verifier.
    /// </summary>
    [TestMethod]
    public void RetrieveToken_ChallengeWithoutVerifier_ReturnsInvalidGrant() {
      FakePkceOAuthService service = new FakePkceOAuthService();
      OAuth2Controller controller = CreateController(service);
      string code = service.StageCode(_RfcChallenge);

      TokenIssuingResult result = controller.RetrieveToken(CreateCodeRequest(code, null));

      Assert.AreEqual("invalid_grant", result.error);
      Assert.IsNull(result.access_token);
    }

    /// <summary>
    /// Downgrade protection: a verifier for a code without challenge is rejected.
    /// </summary>
    [TestMethod]
    public void RetrieveToken_VerifierWithoutChallenge_ReturnsInvalidGrant() {
      FakePkceOAuthService service = new FakePkceOAuthService();
      OAuth2Controller controller = CreateController(service);
      string code = service.StageCode(null);

      TokenIssuingResult result = controller.RetrieveToken(CreateCodeRequest(code, _RfcVerifier));

      Assert.AreEqual("invalid_grant", result.error);
      Assert.IsNull(result.access_token);
    }

    /// <summary>
    /// Backward compatibility: the classic code flow without PKCE still works.
    /// </summary>
    [TestMethod]
    public void RetrieveToken_WithoutPkce_ReturnsToken() {
      FakePkceOAuthService service = new FakePkceOAuthService();
      OAuth2Controller controller = CreateController(service);
      string code = service.StageCode(null);

      TokenIssuingResult result = controller.RetrieveToken(CreateCodeRequest(code, null));

      Assert.IsTrue(string.IsNullOrWhiteSpace(result.error), result.error_description);
      Assert.AreEqual(FakePkceOAuthService.IssuedAccessToken, result.access_token);
    }

    /// <summary>
    /// The (non-standard) GET proxy of the token endpoint also passes the verifier.
    /// </summary>
    [TestMethod]
    public void RetrieveTokenViaGet_ChallengeAndMatchingVerifier_ReturnsToken() {
      FakePkceOAuthService service = new FakePkceOAuthService();
      OAuth2Controller controller = CreateController(service);
      string code = service.StageCode(_RfcChallenge);

      TokenIssuingResult result = controller.RetrieveTokenViaGet(
        "authorization_code", FakePkceOAuthService.ClientId, FakePkceOAuthService.ClientSecret, code, _RfcVerifier
      );

      Assert.IsTrue(string.IsNullOrWhiteSpace(result.error), result.error_description);
      Assert.AreEqual(FakePkceOAuthService.IssuedAccessToken, result.access_token);
    }

    /// <summary>
    /// Creates a controller instance for testing the token endpoint (no HttpContext required).
    /// </summary>
    private static OAuth2Controller CreateController(IOAuthService service) {
      return new OAuth2Controller(NullLogger<OAuth2Controller>.Instance, service, null);
    }

    /// <summary>
    /// Creates the form content of an 'authorization_code' token request.
    /// </summary>
    private static IFormCollection CreateCodeRequest(string code, string codeVerifier) {
      Dictionary<string, StringValues> args = new Dictionary<string, StringValues>();
      args["grant_type"] = "authorization_code";
      args["client_id"] = FakePkceOAuthService.ClientId;
      args["client_secret"] = FakePkceOAuthService.ClientSecret;
      args["code"] = code;
      if (codeVerifier != null) {
        args["code_verifier"] = codeVerifier;
      }
      return new FormCollection(args);
    }

    #endregion

    /// <summary>
    /// Minimal IOAuthService, which only implements the code-flow redemption
    /// (persisting the opaque code challenge together with the code).
    /// </summary>
    private class FakePkceOAuthService : IOAuthService {

      public const string ClientId = "client";
      public const string ClientSecret = "secret";
      public const string IssuedAccessToken = "the-access-token";

      private readonly Dictionary<string, string> _CodeChallengesPerCode = new Dictionary<string, string>();

      /// <summary>
      /// Simulates the creation of a code (like 'TryValidateSessionIdAndCreateRetrievalCode').
      /// </summary>
      public string StageCode(string codeChallenge) {
        bool success = this.TryValidateSessionIdAndCreateRetrievalCode(
          ClientId, "session", new string[] { }, codeChallenge, out string code, out string message
        );
        Assert.IsTrue(success, message);
        return code;
      }

      public bool TryValidateSessionIdAndCreateRetrievalCode(
        string apiClientId, string sessionId, string[] selectedScopes, string codeChallenge,
        out string code, out string message
      ) {
        code = Guid.NewGuid().ToString("N");
        _CodeChallengesPerCode[code] = codeChallenge;
        message = null;
        return true;
      }

      public TokenIssuingResult RetrieveTokenByCode(string clientId, string clientSecret, string code, out string codeChallenge) {
        codeChallenge = null;
        if (clientId != ClientId || clientSecret != ClientSecret) {
          return TokenIssuingResult.FromError("invalid_client", "Unknown client");
        }
        if (code == null || !_CodeChallengesPerCode.TryGetValue(code, out codeChallenge)) {
          return TokenIssuingResult.FromError("invalid_grant", "Invalid Code");
        }
        //make sure the code can only be used once
        _CodeChallengesPerCode.Remove(code);
        TokenIssuingResult result = new TokenIssuingResult();
        result.access_token = IssuedAccessToken;
        result.token_type = "bearer";
        return result;
      }

      public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {
        throw new NotImplementedException();
      }

      public bool TryAuthenticate(
        string apiClientId, string login, string password, bool noPasswordNeeded, string clientProvidedState,
        out string sessionId, out string message
      ) {
        throw new NotImplementedException();
      }

      public bool TryGetAvailableScopesBySessionId(
        string apiClientId, string sessionId, string[] prefferedScopes,
        out ScopeDescriptor[] availableScopes, out string message
      ) {
        throw new NotImplementedException();
      }

      public TokenIssuingResult ValidateClientAndCreateToken(string clientId, string clientSecret, string[] selectedScopes) {
        throw new NotImplementedException();
      }

      public bool TryValidateSessionIdAndCreateToken(
        string apiClientId, string sessionId, string[] selectedScopes, out TokenIssuingResult tokenResult
      ) {
        throw new NotImplementedException();
      }

      public bool TryValidateApiClient(string apiClientId, string apiCallerHost, string redirectUri, out string message) {
        throw new NotImplementedException();
      }

      public TokenIssuingResult CreateFollowUpToken(string refreshToken) {
        throw new NotImplementedException();
      }

    }

  }

}
