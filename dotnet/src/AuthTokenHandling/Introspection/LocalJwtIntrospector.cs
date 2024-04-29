using Jose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Security.AccessTokenHandling {

  public class LocalJwtIntrospector : IAccessTokenIntrospector {

    /// <summary>
    /// The retuned object can be a byte[] or a JWK stucture
    /// </summary>
    /// <param name="rawJwt"></param>
    /// <returns></returns>
    public delegate bool JwtSignatureValidationDelegate(string rawJwt);

    private JwtSignatureValidationDelegate _JwtSignatureValidationMethod;
    private Action<Dictionary<string, object>> _ClaimCustomizer = null;

    public LocalJwtIntrospector(string signKey, Action<Dictionary<string, object>> claimCustomizer = null) {
      _JwtSignatureValidationMethod = (string rawToken) => VerifySignature(rawToken, new Jwk(Encoding.ASCII.GetBytes(signKey)));
      _ClaimCustomizer = claimCustomizer;
    }

    public LocalJwtIntrospector(byte[] signKey, Action<Dictionary<string, object>> claimCustomizer = null) {
      _JwtSignatureValidationMethod = (string rawToken) => VerifySignature(rawToken, new Jwk(signKey));
      _ClaimCustomizer = claimCustomizer;
    }

    public LocalJwtIntrospector(Jwk jsonWebKey, Action<Dictionary<string, object>> claimCustomizer = null) {
      _JwtSignatureValidationMethod = (string rawToken) => VerifySignature(rawToken, jsonWebKey);
      _ClaimCustomizer = claimCustomizer;
    }

    public LocalJwtIntrospector(JwtSignatureValidationDelegate jwtSignatureValidationMethod, Action<Dictionary<string, object>> claimCustomizer = null) {
      _JwtSignatureValidationMethod = jwtSignatureValidationMethod;
      _ClaimCustomizer = claimCustomizer;
    }

    private static bool VerifySignature(string rawJwt, Jwk jsonWebKey) {
      try {
        //this method should implicit check signature and throw if invalid
        string decodedToken = JWT.Decode(rawJwt, jsonWebKey);
        if (!string.IsNullOrWhiteSpace(decodedToken)){
          return true;
        }
      }
      catch (Exception ex){
        Debug.WriteLine($"JWT signature verification failed (Decode-Error): {ex.Message}");
      }
      return false;
    }

    public void IntrospectAccessToken(
      string rawToken, out bool isActive, out Dictionary<string, object> claims
    ) {

      if (_JwtSignatureValidationMethod != null) {
        if (_JwtSignatureValidationMethod.Invoke(rawToken) == false) {
          isActive = false;
          claims = null;
          return;
        }
      }

      var jwtContent = JWT.Payload<Dictionary<string, object>>(rawToken);
      long exp = Convert.ToInt64(jwtContent["exp"]);
      var expirationTimeUtc = new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc).AddSeconds(exp);
      if (DateTime.UtcNow > expirationTimeUtc) {
        isActive = false;
        claims = null;
        return;
      }

      if(_ClaimCustomizer != null) {
        _ClaimCustomizer.Invoke(jwtContent);
      }

      isActive = true;
      claims = jwtContent;
      return;

    }

  }

}
