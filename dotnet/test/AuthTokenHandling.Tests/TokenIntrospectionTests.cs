using System;
using System.Collections.Generic;
#if NET5_0_OR_GREATER
using System.ComponentModel.DataAnnotations;
#endif
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using Jose;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling;
using static Security.AccessTokenHandling.AccessTokenValidator;

namespace Security {

  [TestClass]
  public class TokenIntrospectionTests {

#if NET5_0_OR_GREATER

    private const string _SignKey = "2A0C4D2F8A8A8B4C7F0F4D4C1A6B9F4C7A0C6B"; 

    [TestMethod]
    public void TestTokenIntrospection2() {
      MethodInfo myMethod = this.GetType().GetMethod(nameof(TestTokenIntrospection2));

      IAccessTokenIntrospector introspector = new LocalJwtIntrospector((T)=> true);
      var validator = new TokenValidationRulesetBasedValidator();

      int callNumer = 1;
      AuditingHook auditingHook = (
        (
          calledMethod, callingMachine, outcome, discoveredSubjectIdentity,
          permittedScopes, requiredScopes, fromCache
        ) => {
          Assert.IsFalse(fromCache);//cache has been set to 0 minutes for unit tests
          switch (callNumer) {
            case 1:
              //because "Baz" inside of the scope-claim doesnt have the prifix 'API:'
              Assert.AreEqual(ValidationOutcome.AccessDeniedMissingPrivileges, outcome);
              Assert.AreEqual("Max4711", discoveredSubjectIdentity);
              break;
            case 2:
              Assert.AreEqual(ValidationOutcome.AccessGranted, outcome);
              Assert.AreEqual("Max4711", discoveredSubjectIdentity);
              Assert.IsTrue(requiredScopes.Contains("API:Bar"));
              Assert.IsTrue(requiredScopes.Contains("API:Bar"));
              Assert.IsTrue(permittedScopes.Contains("API:Bar"));
              Assert.IsTrue(permittedScopes.Contains("FromHook"));
              break;
            case 3:
              //EXPIRED
              Assert.AreEqual(ValidationOutcome.AccessDeniedTokenInvalid, outcome);
              Assert.IsTrue(requiredScopes.Contains("API:Bar"));
              Assert.IsTrue(permittedScopes.Count() == 0);
              break;
          }
          callNumer++;
        }
      );

      //setup the token validation environment
      AccessTokenValidator.ConfigureTokenValidation(
        introspector,
        (opt) => {
          opt.UseScopeVisitor((string subject, List<string> permittedScopes) => {
            permittedScopes.Add("FromHook");
          });
          opt.EnableAnonymousSubject("(anonymous)");
          opt.ChangeCachingLifetime(0);
          opt.UseAuditingHook(auditingHook);
        }
      );

      string tokenA = this.GenerateTestToken("UnitTest", "Max4711", "API:Foo API:Bar Baz Tenant:123");

      ValidationOutcome result1 = AccessTokenValidator.TryValidateTokenAndEvaluateScopes(
       tokenA, myMethod.DeclaringType, myMethod, "localhost", "Bar", "Baz"
      );

      ValidationOutcome result2 = AccessTokenValidator.TryValidateTokenAndEvaluateScopes(
       tokenA, myMethod.DeclaringType, myMethod, "localhost", "Bar"
      );

      string expiredToken = this.GenerateTestToken(
        "UnitTest", "Max4711", "API:Foo API:Bar Baz Tenant:123", expired: true
      );

      ValidationOutcome result3 = AccessTokenValidator.TryValidateTokenAndEvaluateScopes(
       expiredToken, myMethod.DeclaringType, myMethod, "localhost", "Bar"
      );

      //setup the token validation environment to use the config-based way
      //AccessTokenValidator.ConfigureTokenIntrospection(
      //  introspector,
      //  scopeEnumerationHook: validator.EnumerateScopes,
      //  anonymousSubjectName: "(anonymous)",
      //  introspectionResultCachingMinutes: 0,
      //  auditingHook: auditingHook
      //);

    }

    private string GenerateTestToken(string issuer, string subject, string scope, bool expired = false) {

      JwtContent tokenContent = new JwtContent();
      tokenContent.iss = issuer;
      tokenContent.sub = subject;
      tokenContent.scope = scope;

      if (expired) {
        tokenContent.exp = DateTimeOffset.Now.ToUnixTimeSeconds() - 10;//expired since 10 seconds
      }
      else {
        tokenContent.exp = DateTimeOffset.Now.ToUnixTimeSeconds() + 10; //valid for the next 10 seconds
      }

      string rawToken = JWT.Encode(tokenContent, Encoding.ASCII.GetBytes(_SignKey), JwsAlgorithm.HS256);

      return rawToken;
    }

#endif

    [TestMethod]
    public void TestIssuing() {

    }

    //[TestMethod]
    public void TestTokenIntrospection() {
      const string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYXN0ZXIiLCJzdWIiOm51bGwsImV4cCI6MTY4NzI2NTA0NywiaWF0IjoxNjg3MTc4NjQ3LCJhdWQiOiJyZS1kZWZpbmUtaXQuZGUiLCJzY29wZSI6IkFQSTpBY2Nlc3NUb2tlblZhbGlkYXRvciBBUEk6VXNlckFkbWluc3RyYXRpb24gVXNlcjoqIEFQSTpFbnZpcm9ubWVudFNldHVwIEFQSTpFbnZpcm9ubWVudEFkbWluaXN0cmF0aW9uIFNlY0VudjoqIn0.AGt_ZeR-l6hH6J5PtfXV5RPv5tv8lBsUk1n94hQ7AO8";

      var introspector = new OAuthTokenIntrospectionEndpointCaller(() => "https://localhost:44351/oauth/introspect");

      introspector.IntrospectAccessToken(token, out var isActive, out var claims);

      Debugger.Break();

    }

  }

}
