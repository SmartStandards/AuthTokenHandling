using Jose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Security.AccessTokenHandling {

  public class LocalJwtIssuer : IAccessTokenIssuer {

    private ClaimCustomizerDelegate _ClaimCustomizer = null;
    private Func<object,string> _EncodingMethod = null;
    private int _ExpMinutes = 10;

    public LocalJwtIssuer(byte[] signKey, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {
      _ClaimCustomizer = (Dictionary<string, object> requestedClaims, Dictionary<string, object> claimsToUse, ref bool mergeRequestedClaims) => {
        mergeRequestedClaims = passtroughAllRequestedClaims;
        if(!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          requestedClaims["iss"] = enforcedIssuer;
          claimsToUse["iss"] = enforcedIssuer;
        }
      };
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }
    public LocalJwtIssuer(byte[] signKey, JwsAlgorithm signAlg, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {
      _ClaimCustomizer = (Dictionary<string, object> requestedClaims, Dictionary<string, object> claimsToUse, ref bool mergeRequestedClaims) => {
        mergeRequestedClaims = passtroughAllRequestedClaims;
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          requestedClaims["iss"] = enforcedIssuer;
          claimsToUse["iss"] = enforcedIssuer;
        }
      };
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }
    public LocalJwtIssuer(byte[] signKey, int expMinutes, ClaimCustomizerDelegate claimCustomizer) {
      _ClaimCustomizer = claimCustomizer;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }
    public LocalJwtIssuer(byte[] signKey, JwsAlgorithm signAlg, int expMinutes, ClaimCustomizerDelegate claimCustomizer) {
      _ClaimCustomizer = claimCustomizer;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

  #region " Convenience-Constructors with JWK-Structure "

    public LocalJwtIssuer(Jwk signKey, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {
      _ClaimCustomizer = (Dictionary<string, object> requestedClaims, Dictionary<string, object> claimsToUse, ref bool mergeRequestedClaims) => {
        mergeRequestedClaims = passtroughAllRequestedClaims;
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          requestedClaims["iss"] = enforcedIssuer;
          claimsToUse["iss"] = enforcedIssuer;
        }
      };
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }

    public LocalJwtIssuer(Jwk signKey, JwsAlgorithm signAlg, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {
      _ClaimCustomizer = (Dictionary<string, object> requestedClaims, Dictionary<string, object> claimsToUse, ref bool mergeRequestedClaims) => {
        mergeRequestedClaims = passtroughAllRequestedClaims;
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          requestedClaims["iss"] = enforcedIssuer;
          claimsToUse["iss"] = enforcedIssuer;
        }
      };
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

    public LocalJwtIssuer(Jwk signKey, int expMinutes, ClaimCustomizerDelegate claimCustomizer) {
      _ClaimCustomizer = claimCustomizer;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }

    public LocalJwtIssuer(Jwk signKey, JwsAlgorithm signAlg, int expMinutes, ClaimCustomizerDelegate claimCustomizer) {
      _ClaimCustomizer = claimCustomizer;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

    public string RequestAccessToken() {
      return this.RequestAccessToken(null);
    }

  #endregion

    public string RequestAccessToken(Dictionary<string, object> claimsToRequest) {
      var claimsToUse = new Dictionary<string, object>();
      if (_ClaimCustomizer != null) {
        if (claimsToRequest == null) {
          claimsToRequest = new Dictionary<string, object>();
        }
        bool merge = false;
        _ClaimCustomizer.Invoke(claimsToRequest, claimsToUse, ref merge);
        if (merge) {
          if (claimsToUse.Count == 0) {
            claimsToUse = claimsToRequest;
          }
          else {
            foreach (var customClaim in claimsToRequest) {
              object value = customClaim.Value;
              //special case: scope's needs to be merged!
              if(customClaim.Key == "scope" && customClaim.Value != null && claimsToUse.ContainsKey("scope")) {
                var scopesToUse = claimsToUse["scope"].ToString().Split(' ');
                var customScopes = customClaim.Value.ToString().Split(' ');
                value = string.Join(" ", scopesToUse.Union(customScopes).Where((s) => !string.IsNullOrWhiteSpace(s)).Distinct());
              } 
              if(value == null) {
                if (claimsToUse.ContainsKey(customClaim.Key)) {
                  claimsToUse.Remove(customClaim.Key);
                }
              }
              else {
                claimsToUse[customClaim.Key] = value;
              }
            }
          }
        }
      }

      claimsToUse["iat"] = CalculateUnixTimestamp(DateTime.UtcNow);
      claimsToUse["exp"] = CalculateUnixTimestamp(DateTime.UtcNow.AddMinutes(_ExpMinutes));

      if (!claimsToUse.ContainsKey("sub") || claimsToUse["sub"] == null) {
        claimsToUse["sub"] = "(anonymous)";
      }
      if (!claimsToUse.ContainsKey("iss") || claimsToUse["iss"] == null) {
        claimsToUse["iss"] = "(self-signed)";
      }
      if (!claimsToUse.ContainsKey("aud") || claimsToUse["aud"] == null) {
        claimsToUse["aud"] = "";
      }
      if (!claimsToUse.ContainsKey("jti") || claimsToUse["jti"] == null) {
        claimsToUse["jti"] = Guid.NewGuid().ToString().ToLower().Replace("-", "");
      }

      string jwt = _EncodingMethod.Invoke(claimsToUse);

      return jwt;
    }

    private static DateTime _UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
    private static long CalculateUnixTimestamp(DateTime input) {
      TimeSpan diff = input - _UnixEpoch;
      return System.Convert.ToInt64(diff.TotalSeconds);
    }

  }

}
