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
    /// <param name="rawJwt">CAN BE NULL OR EMPTY!!!</param>
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
      if (string.IsNullOrWhiteSpace(rawJwt)) {
        return false;
      }
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

      claims = new Dictionary<string, object>();

      if (_JwtSignatureValidationMethod != null) {
        if (_JwtSignatureValidationMethod.Invoke(rawToken)) {
          isActive = true;
        }
        else {
          isActive = false;
          claims = null;
          claims["inactive_reason"] = $"Signature verification failed";
          return;
        }
      }
      else if (string.IsNullOrWhiteSpace(rawToken)) {
        isActive = false;
        return;
      }
      else {
        isActive = true; //no signature validation method configured - assume valid
      }

      Dictionary<string, object> jwtContent;
      if (string.IsNullOrWhiteSpace(rawToken)) {
        jwtContent = new Dictionary<string, object>();
      }
      else {
        jwtContent = JWT.Payload<Dictionary<string, object>>(rawToken);
      }

      if (jwtContent.ContainsKey("exp")) {
        claims["exp"] = jwtContent["exp"];
        long exp = Convert.ToInt64(jwtContent["exp"]);
        DateTime expirationTimeUtc = new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc).AddSeconds(exp);
        if (DateTime.UtcNow > expirationTimeUtc) {
          isActive = false;
          claims = new Dictionary<string, object>();
          claims["inactive_reason"] = $"Expired (at {expirationTimeUtc.ToString("u")})";
          return;
        }
      }

      if (jwtContent.ContainsKey("nbf")) {
        claims["nbf"] = jwtContent["nbf"];
        long nbf = Convert.ToInt64(jwtContent["nbf"]);
        DateTime notBeforeTimeUtc = new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc).AddSeconds(nbf);
        if (DateTime.UtcNow < notBeforeTimeUtc) {
          isActive = false;
          claims = new Dictionary<string, object>();
          claims["inactive_reason"] = $"Valid in future (at {notBeforeTimeUtc.ToString("u")})";
          return;
        }
      }

      if (_ClaimCustomizer != null) {
        _ClaimCustomizer.Invoke(jwtContent);
      }

      claims = jwtContent;
    }

  }

}
