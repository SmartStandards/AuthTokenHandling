using Jose;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.OAuth.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Security.AccessTokenHandling {

  public class LocalJwtIssuer : IAccessTokenIssuer {

    private Action<ClaimApprovalContext> _ClaimApprovalHandler = null;
    private Func<object,string> _EncodingMethod = null;
    private int _ExpMinutes = 10;

    public LocalJwtIssuer(
      byte[] signKey, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null
    ) {

      _ClaimApprovalHandler = (ClaimApprovalContext ctx) => {
        if (passtroughAllRequestedClaims) {
          ctx.TakeOverAllRequestedClaims();
        }
        else {
          ctx.TakeOverRequestedClaims("aud", "sub", "iss");
        }
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          ctx.SetValueToUse("iss", enforcedIssuer);
        }
      };

      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }

    public LocalJwtIssuer(byte[] signKey, JwsAlgorithm signAlg, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {

      _ClaimApprovalHandler = (ClaimApprovalContext ctx) => {
        if (passtroughAllRequestedClaims) {
          ctx.TakeOverAllRequestedClaims();
        }
        else {
          ctx.TakeOverRequestedClaims("aud", "sub", "iss");
        }
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          ctx.SetValueToUse("iss", enforcedIssuer);
        }
      };

      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

    public LocalJwtIssuer(byte[] signKey, int expMinutes, Action<ClaimApprovalContext> claimApprovalHandler) {
      _ClaimApprovalHandler = claimApprovalHandler;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }

    public LocalJwtIssuer(byte[] signKey, JwsAlgorithm signAlg, int expMinutes, Action<ClaimApprovalContext> claimApprovalHandler) {
      _ClaimApprovalHandler = claimApprovalHandler;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

  #region " Convenience-Constructors with JWK-Structure "

    public LocalJwtIssuer(Jwk signKey, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {
     
      _ClaimApprovalHandler = (ClaimApprovalContext ctx) => {
        if (passtroughAllRequestedClaims) {
          ctx.TakeOverAllRequestedClaims();
        }
        else {
          ctx.TakeOverRequestedClaims("aud", "sub", "iss");
        }
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          ctx.SetValueToUse("iss", enforcedIssuer);
        }
      };

      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }

    public LocalJwtIssuer(Jwk signKey, JwsAlgorithm signAlg, int expMinutes, bool passtroughAllRequestedClaims = false, string enforcedIssuer = null) {
    
      _ClaimApprovalHandler = (ClaimApprovalContext ctx) => {
        if (passtroughAllRequestedClaims) {
          ctx.TakeOverAllRequestedClaims();
        }
        else {
          ctx.TakeOverRequestedClaims("aud", "sub", "iss");
        }
        if (!string.IsNullOrWhiteSpace(enforcedIssuer)) {
          ctx.SetValueToUse("iss", enforcedIssuer);
        }
      };

      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

    public LocalJwtIssuer(Jwk signKey, int expMinutes, Action<ClaimApprovalContext> claimApprovalHandler) {
      _ClaimApprovalHandler = claimApprovalHandler;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, JwsAlgorithm.HS256);
    }

    public LocalJwtIssuer(Jwk signKey, JwsAlgorithm signAlg, int expMinutes, Action<ClaimApprovalContext> claimApprovalHandler) {
      _ClaimApprovalHandler = claimApprovalHandler;
      _ExpMinutes = expMinutes;
      _EncodingMethod = (payload) => JWT.Encode(payload, signKey, signAlg);
    }

    public bool TryRequestAccessToken(out TokenIssuingResult accessToken) {
      return this.TryRequestAccessToken(null, out accessToken);
    }

  #endregion

    public bool TryRequestAccessToken(Dictionary<string, object> claimsToRequest, out TokenIssuingResult result) {

      Dictionary<string, object> claimsToUse = ClaimApprovalContext.ProcessRequestedClaims(claimsToRequest, _ClaimApprovalHandler);

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
      result = new TokenIssuingResult();
      result.token_type = "Bearer";
      result.scope = (claimsToUse.ContainsKey("scope") && claimsToUse["scope"] != null) ? claimsToUse["scope"].ToString() : null;
      result.access_token = jwt;
      result.expires_in = (_ExpMinutes * 60);

      return true;
    }

    private static DateTime _UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
    private static long CalculateUnixTimestamp(DateTime input) {
      TimeSpan diff = input - _UnixEpoch;
      return System.Convert.ToInt64(diff.TotalSeconds);
    }

  }

}
