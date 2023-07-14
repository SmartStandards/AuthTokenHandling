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

    public LocalJwtIntrospector(string signKey) {
      _JwtSignatureValidationMethod = (string rawToken) => VerifySignature(rawToken,new Jwk(Encoding.ASCII.GetBytes(signKey)));
    }

    public LocalJwtIntrospector(byte[] signKey) {
      _JwtSignatureValidationMethod = (string rawToken) => VerifySignature(rawToken, new Jwk(signKey));
    }

    public LocalJwtIntrospector(Jwk jsonWebKey) {
      _JwtSignatureValidationMethod = (string rawToken) => VerifySignature(rawToken, jsonWebKey);
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

    public LocalJwtIntrospector(JwtSignatureValidationDelegate jwtSignatureValidationMethod) {
      _JwtSignatureValidationMethod = jwtSignatureValidationMethod;
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

      isActive = true;
      claims = jwtContent;
      return;

    }

  }

}
