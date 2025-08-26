using Jose;
using Security.AccessTokenHandling.OAuthServer;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Security.AccessTokenHandling {

  public static class IssuerFactory {

    public static IAccessTokenIssuer CreateFromConfig(AuthTokenConfig config) {
      
      if (string.IsNullOrWhiteSpace(config.IssueMode)) {
        return new DummyIssuer();
      }

      //convert string-values to spefic value-types for known claims
      Dictionary<string, object> convertedClaims = null;
      if (config.Claims != null) {
        foreach (var configuredClaim in config.Claims) {
          if (convertedClaims == null) {
            convertedClaims = new Dictionary<string, object>();
          }
          convertedClaims[configuredClaim.Key] = configuredClaim.Value;
          if (configuredClaim.Key.Equals("jti", StringComparison.InvariantCultureIgnoreCase)) {
            if (long.TryParse(configuredClaim.Value, out var parsed)) {
              convertedClaims[configuredClaim.Key] = parsed;
            }
          }
        }
      }

      if (config.IssueMode.Equals(WellknownIssuingModes.LOCAL_JWT_GENERATION, StringComparison.InvariantCultureIgnoreCase)) {

        if (string.IsNullOrWhiteSpace(config.JwtValidationKey)) {
          throw new ArgumentException($"'{nameof(config.JwtValidationKey)}' must not be empty!");
        }

        return new LocalJwtIssuer(
          Encoding.ASCII.GetBytes(config.JwtSelfSignKey),
          (JwsAlgorithm) Enum.Parse(typeof(JwsAlgorithm), config.JwtSelfSignAlg, true),
          config.JwtExpMinutes,
          (Dictionary<string, object> requestedClaims, Dictionary<string, object> claimsToUse, ref bool mergeRequestedClaims) => {
            if (convertedClaims != null) {
              foreach (var configuredClaim in convertedClaims) {
                claimsToUse[configuredClaim.Key] = configuredClaim.Value;
              }
            }
          }
        );

      }
      else if (config.IssueMode.Equals(WellknownIssuingModes.LOCAL_JWT_GENERATION, StringComparison.InvariantCultureIgnoreCase)) {

        if (string.IsNullOrWhiteSpace(config.JwtValidationKey)) {
          throw new ArgumentException($"'{nameof(config.JwtValidationKey)}' must not be empty!");
        }

        return new LocalJwtIssuer(
          Encoding.ASCII.GetBytes(config.JwtValidationKey),
          config.JwtExpMinutes,
          (Dictionary<string, object> requestedClaims, Dictionary<string, object> claimsToUse, ref bool mergeRequestedClaims) => {
            if (convertedClaims != null) {
              foreach (var configuredClaim in convertedClaims) {
                claimsToUse[configuredClaim.Key] = configuredClaim.Value;
              }
            }
          }
        );

      }
      //else if (
      //  config.ValidationMode.Equals(WellknownIssuingModes.oa, StringComparison.InvariantCultureIgnoreCase) ||
      //  config.ValidationMode.Equals(WellknownIssuingModes.OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY, StringComparison.InvariantCultureIgnoreCase)
      //) {

      //  UrlGetterMethod urlGetter = DefaultUrlGetter;
      //  if (string.IsNullOrWhiteSpace(config.ValidationEndpointUrl)) {
      //    if (urlGetter == null) {
      //      throw new ArgumentException($"'{nameof(config.ValidationEndpointUrl)}' must not be empty!");
      //    }
      //  }
      //  else {
      //    urlGetter = (t) => config.ValidationEndpointUrl;
      //  }

      //  AuthHeaderGetterMethod ahGetter = DefaultAuthHeaderGetter;
      //  if (string.IsNullOrWhiteSpace(config.validationEndpointAuthorization)) {
      //    if (urlGetter == null) {
      //      ahGetter = (t) => null;
      //    }
      //  }
      //  else if (config.validationEndpointAuthorization.Contains("%")) {
      //    throw new NotImplementedException("%-placholders to address forign-authtokensources are not jet implemented");
      //  }
      //  else {
      //    ahGetter = (t) => config.validationEndpointAuthorization;
      //  }

      //  OAuthTokenIntrospectionEndpointCaller introspector = new OAuthTokenIntrospectionEndpointCaller(
      //    () => urlGetter.Invoke(typeof(IAccessTokenIntrospector)),
      //    () => ahGetter.Invoke(typeof(IAccessTokenIntrospector))
      //  );

      //  if (config.ValidationMode.Equals(WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY, StringComparison.InvariantCultureIgnoreCase)) {
      //    introspector.UseHttpGet = true;
      //  }

      //  return introspector;
      //}
      //else if (config.IssueMode.Equals(WellknownIssuingModes., StringComparison.InvariantCultureIgnoreCase)) {
      //  return new DummyIssuer();
      //}
      //else if (config.ValidationMode.Equals(WellknownValidationModes.GITHUB_VALIDATION_ENDPOINT, StringComparison.InvariantCultureIgnoreCase)) {
      //}
      else {
        throw new NotImplementedException($"A '{nameof(config.IssueMode)}' called '{config.IssueMode}' is not jet implemented!");
      }
    }

    #region " dynamic Url- & Auth- resolving (for OAuth-EP only) "

    public delegate string AuthHeaderGetterMethod(
      Type contractType
    );
    public static AuthHeaderGetterMethod DefaultAuthHeaderGetter { get; set; } = (t) => null;

    public delegate string UrlGetterMethod(
      Type contractType
    );
    public static UrlGetterMethod DefaultUrlGetter { get; set; } = (t) => null;

    #endregion

    private class DummyIssuer : IAccessTokenIssuer {

      public DummyIssuer() {
      }

      public bool TryRequestAccessToken(out TokenIssuingResult result) {
        result = new TokenIssuingResult();
        return true;
      }

      public bool TryRequestAccessToken(Dictionary<string, object> claimsToRequest, out TokenIssuingResult result) {
        result = new TokenIssuingResult();
        return true;
      }

    }

  }

}
