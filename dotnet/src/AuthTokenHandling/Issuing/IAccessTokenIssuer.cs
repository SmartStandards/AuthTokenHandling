using Security.AccessTokenHandling.OAuth;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;

[assembly: InternalsVisibleTo("SmartStandards.AuthTokenHandling.WinFormsClient")]

namespace Security.AccessTokenHandling {

  public interface IAccessTokenIssuer {

    bool TryRequestAccessToken(out TokenIssuingResult result);

    bool TryRequestAccessToken(
      Dictionary<String, object> claimsToRequest, out TokenIssuingResult result
    );

  }

  public static class AccessTokenIssuerExtensions {

    //[Obsolete("Use overload with 'Dictionary<string, OBJECT>'")]
    //public static bool TryRequestAccessToken(
    //  this IAccessTokenIssuer issuer,
    //  Dictionary<string, string> claimsToRequest, out TokenIssuingResult result
    //) {
    //  Dictionary<string, object> mappedDict = new Dictionary<string, object>();
    //  foreach (var claim in claimsToRequest) {
    //    mappedDict[claim.Key] = claim.Value;
    //  }
    //  return issuer.TryRequestAccessToken(mappedDict, out result);
    //}

    public static bool RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string subject, string audience,
      out TokenIssuingResult result
    ) {
      return issuer.RequestAccessToken(null, subject, audience, out result);
    }

    public static bool RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string subject, string audience, string[] scope,
      out TokenIssuingResult result
    ) {
      return issuer.RequestAccessToken(null, subject, audience, scope, out result);
    }

    public static bool RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string issuerName, string subject, string audience,
      out TokenIssuingResult result
    ) {
      return issuer.RequestAccessToken(issuerName, subject, audience, null, out result);
    }

    public static bool RequestAccessToken(
      this IAccessTokenIssuer issuer,
      string issuerName, string subject, string audience, string[] scope,
      out TokenIssuingResult result
    ) {

      Dictionary<String, object> claimsToRequest = new Dictionary<String, object>();
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

      return issuer.TryRequestAccessToken(claimsToRequest, out result);
    }

  }

}
