using System;
using System.Collections.Generic;
using System.Net.Http.Headers;

namespace Security.AccessTokenHandling {

  /// <summary></summary>
  /// <param name="requestedClaims"> Not more than a 'whish', comming from the caller which requested a token.</param>
  /// <param name="claimsToUse"> That claims, which will be included in the JWT.</param>
  /// <param name="mergeRequestedClaims">
  /// Set this to true (opt-in), to approve all entries which are left within 'requestedClaims' and
  /// let the issuer copy them over the claimsToUse ('requestedClaims' will win!). 
  /// This is a convenience, which allows you just to cleanup the 'requestedClaims' and lay back!
  /// SPECIAL BEHAVIOUR: ('scope'-expressions will automatically concatinated).
  /// </param>
  public delegate void ClaimCustomizerDelegate(
     Dictionary<string, object> requestedClaims,
     Dictionary<string, object> claimsToUse,
     ref bool mergeRequestedClaims
  );

  public interface IAccessTokenIssuer {

    string RequestAccessToken();

    string RequestAccessToken(
      Dictionary<String, object> claimsToRequest
    );

  }

  public static class AccessTokenIssuerExtensions {

    public static string RequestAccessToken(
      this IAccessTokenIssuer issuer,
      Dictionary<string, string> claimsToRequest
    ) {
      var mappedDict = new Dictionary<string, object>();
      foreach (var claim in claimsToRequest) {
        mappedDict[claim.Key] = claim.Value;
      }
      return issuer.RequestAccessToken(mappedDict);
    }

    public static string RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string subject, string audience
    ) {
      return issuer.RequestAccessToken(null, subject, audience);
    }

    public static string RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string subject, string audience, string[] scope
    ) {
      return issuer.RequestAccessToken(null, subject, audience, scope);
    }

    public static string RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string issuerName, string subject, string audience
    ) {
      return issuer.RequestAccessToken(issuerName, subject, audience, null);
    }

    public static string RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string issuerName, string subject, string audience, string[] scope
    ) {
      var claimsToRequest = new Dictionary<String, object>();
      if (!string.IsNullOrWhiteSpace(issuerName)) {
        claimsToRequest["iss"] = issuerName;
      }
      if (!string.IsNullOrWhiteSpace(subject)) {
        claimsToRequest["sub"] = subject;
      }
      if (!string.IsNullOrWhiteSpace(audience)) {
        claimsToRequest["aud"] = audience;
      }
      if (scope != null) {
        string raw = string.Join(" ", scope);
        if (!string.IsNullOrWhiteSpace(raw)) {
          claimsToRequest["scope"] = raw;
        }
      }
      return issuer.RequestAccessToken(claimsToRequest);
    }

  }

}
