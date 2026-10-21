using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Security.AccessTokenHandling {

  public static class IntrospectorFactory {

    public static IAccessTokenIntrospector CreateFromConfig(AuthTokenConfig config) {
      
      if (string.IsNullOrWhiteSpace(config.ValidationMode)) {
        config.ValidationMode = WellknownValidationModes.IMPLICIT_WHEN_USED;
      }

      //convert string-values to spefic value-types for known claims
      Dictionary<string,object> convertedClaims = null;
      if (config.Claims != null) {
        foreach (var configuredClaim in config.Claims) {
          if (convertedClaims == null) {
            convertedClaims = new Dictionary<string, object>();
          }
          convertedClaims[configuredClaim.Key] = configuredClaim.Value;
          if (configuredClaim.Key.Equals("jti", StringComparison.InvariantCultureIgnoreCase)) {
            if(long.TryParse(configuredClaim.Value, out var parsed)) {
              convertedClaims[configuredClaim.Key] = parsed;
            }
          }
        }
      }

      if (config.ValidationMode.Equals(WellknownValidationModes.LOCAL_JWT_VALIDATION, StringComparison.InvariantCultureIgnoreCase)) {
       
        if (string.IsNullOrWhiteSpace(config.JwtValidationKey)) {
          throw new ArgumentException($"'{nameof(config.JwtValidationKey)}' must not be empty!");
        }

        //TODO: byte-arraa wie parsen?
        return new LocalJwtIntrospector(
          config.JwtValidationKey,
          (claims) => {
            if(convertedClaims != null) {
              foreach (var configuredClaim in convertedClaims) {
                claims[configuredClaim.Key] = configuredClaim.Value;
              }
            }
          }
        );

      }
      else if (
        config.ValidationMode.Equals(WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT, StringComparison.InvariantCultureIgnoreCase) ||
        config.ValidationMode.Equals(WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY, StringComparison.InvariantCultureIgnoreCase)
      ) {

        //shortcut for an introspection endpoint which is served by an OAuth server within the same process
        IAccessTokenIntrospector inProcessIntrospector;
        if (TryGetInProcessIntrospector(config.ValidationEndpointUrl, out inProcessIntrospector)) {
          return inProcessIntrospector;
        }

        UrlGetterMethod urlGetter = DefaultUrlGetter;
        if (string.IsNullOrWhiteSpace(config.ValidationEndpointUrl)) {
          if (urlGetter == null) {
            throw new ArgumentException($"'{nameof(config.ValidationEndpointUrl)}' must not be empty!");
          }
        }
        else {
          urlGetter = (t) => config.ValidationEndpointUrl;
        }

        AuthHeaderGetterMethod ahGetter = DefaultAuthHeaderGetter;
        if (string.IsNullOrWhiteSpace(config.validationEndpointAuthorization)) {
          if (urlGetter == null) {
            ahGetter = (t) => null;
          }
        }
        else if(config.validationEndpointAuthorization.Contains("%")) {
          throw new NotImplementedException("%-placholders to address forign-authtokensources are not jet implemented");
        }
        else {
          ahGetter = (t) => config.validationEndpointAuthorization;
        }

        OAuthTokenIntrospectionEndpointCaller introspector = new OAuthTokenIntrospectionEndpointCaller(
          () => urlGetter.Invoke(typeof(IAccessTokenIntrospector)),
          () => ahGetter.Invoke(typeof(IAccessTokenIntrospector))
        );

        if (config.ValidationMode.Equals(WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY, StringComparison.InvariantCultureIgnoreCase)) {
          introspector.UseHttpGet = true;
        }

        return introspector;
      }
      else if (config.ValidationMode.Equals(WellknownValidationModes.IMPLICIT_WHEN_USED, StringComparison.InvariantCultureIgnoreCase)) {
        return new DummyIntrospector(convertedClaims);
      }
      //else if (config.ValidationMode.Equals(WellknownValidationModes.GITHUB_VALIDATION_ENDPOINT, StringComparison.InvariantCultureIgnoreCase)) {
      //}
      else {
        throw new NotImplementedException($"A '{nameof(config.ValidationMode)}' called '{config.ValidationMode}' is not jet implemented!");
      }
    }

    #region " dynamic Url- & Auth- resolving (for Introspection-EP only) "

    public delegate string AuthHeaderGetterMethod(
      Type contractType
    );
    public static AuthHeaderGetterMethod DefaultAuthHeaderGetter { get; set; } = (t) => null;

    public delegate string UrlGetterMethod(
      Type contractType
    );
    public static UrlGetterMethod DefaultUrlGetter { get; set; } = (t) => null;

    #endregion

    #region " in-process introspection endpoints "

    private static readonly Dictionary<string, IAccessTokenIntrospector> _InProcessIntrospectors = (
      new Dictionary<string, IAccessTokenIntrospector>(StringComparer.OrdinalIgnoreCase)
    );

    /// <summary>
    /// Registers an introspector, which is used instead of an HTTP call, whenever a config with the
    /// validation mode 'OAUTH_INTROSPECTION_ENDPOINT' points to exactly this 'validationEndpointUrl'
    /// (e.g. an OAuth server hosted within the same process). Passing null removes the registration.
    /// </summary>
    public static void RegisterInProcessIntrospector(string validationEndpointUrl, IAccessTokenIntrospector introspector) {
      if (string.IsNullOrWhiteSpace(validationEndpointUrl)) {
        throw new ArgumentException($"'{nameof(validationEndpointUrl)}' must not be empty!");
      }
      lock (_InProcessIntrospectors) {
        if (introspector == null) {
          _InProcessIntrospectors.Remove(validationEndpointUrl);
        }
        else {
          _InProcessIntrospectors[validationEndpointUrl] = introspector;
        }
      }
    }

    /// <summary>
    /// Looks up an introspector registered via 'RegisterInProcessIntrospector'.
    /// </summary>
    private static bool TryGetInProcessIntrospector(string validationEndpointUrl, out IAccessTokenIntrospector introspector) {
      introspector = null;
      if (string.IsNullOrWhiteSpace(validationEndpointUrl)) {
        return false;
      }
      lock (_InProcessIntrospectors) {
        return _InProcessIntrospectors.TryGetValue(validationEndpointUrl, out introspector);
      }
    }

    #endregion

    private class DummyIntrospector : IAccessTokenIntrospector {

      private Dictionary<string, object> _PredefinedClaims = null;

      public DummyIntrospector() {
        _PredefinedClaims = null;
      }

      public DummyIntrospector(Dictionary<string, object> predefinedClaims) {
        _PredefinedClaims = predefinedClaims;
      }

      public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {
        isActive = true;
        claims = new Dictionary<string, object>();
        if (_PredefinedClaims != null) {
          foreach (var predefinedClaim in _PredefinedClaims) {
            claims[predefinedClaim.Key] = predefinedClaim.Value;
          }
        }
      }

    }

  }

}
