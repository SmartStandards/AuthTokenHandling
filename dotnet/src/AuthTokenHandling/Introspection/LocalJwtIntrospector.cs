using Jose;
using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling {

  public class LocalJwtIntrospector : IAccessTokenIntrospector {

    /// <summary>
    /// The retuned object can be a byte[] or a JWK stucture
    /// </summary>
    /// <param name="rawJwt"></param>
    /// <returns></returns>
    public delegate bool JwtSignatureValidationDelegate(string rawJwt);

    private JwtSignatureValidationDelegate _JwtSignatureValidationMethod;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtSignatureValidationMethod">
    ///    if not provided, then the signature CANNOT BE VERIFIED, THIS CAN BE A RISK!
    /// </param>
    public LocalJwtIntrospector(JwtSignatureValidationDelegate jwtSignatureValidationMethod = null) {
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
