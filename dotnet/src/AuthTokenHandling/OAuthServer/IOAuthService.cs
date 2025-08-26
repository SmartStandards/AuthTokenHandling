using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling.OAuthServer {

  //INFO: liegt bewusst in 'AuthTokenHandling' anstatt 'AuthTokenHandling.MvcSupport',
  //weil die serverseitige Implementierung wahrscheinlich nicht im MVC Serviceprojekt, sondern in einer
  //technologieunabhängigen Assembly leben wird. Letzterer wollen wir keine sub-Referenzen auf MVC Artefakte 
  //aufzwingen, nur weil sie dieses Interface addressieren muss. Wenn überhaupt, müsste dieses Interface
  //in eine ebenfalls technologieunabhängigen 'AuthTokenHandling.Server' assembly (wäre aktuell aber oversized)

  public interface IOAuthService : IAccessTokenIntrospector {



    /// <summary>
    /// should return a sessionOtp
    /// </summary>
    /// <param name="apiClientId"></param>
    /// <param name="login"></param>
    /// <param name="password"> is empty when noPasswordNeeded</param>
    /// <param name="noPasswordNeeded"> is true when windows pass-trough has already been processed</param>
    /// <param name="clientProvidedState"></param>
    /// <param name="sessionId"></param>
    /// <param name="message"></param>
    /// <returns></returns>
    bool TryAuthenticate(
      string apiClientId,
      string login,
      string password,
      bool noPasswordNeeded,
      string clientProvidedState,
      out string sessionId,
      out string message
    );

    bool TryGetAvailableScopesBySessionId(
      string apiClientId,
      string sessionId,
      string[] prefferedScopes,
      out ScopeDescriptor[] availableScopes,
      out string message
    );

    TokenIssuingResult ValidateClientAndCreateToken(
      string clientId, string clientSecret, string[] selectedScopes
    );

    bool TryValidateSessionIdAndCreateToken(
      string apiClientId, string sessionId, string[] selectedScopes,
      out TokenIssuingResult tokenResult
    );

    bool TryValidateSessionIdAndCreateRetrievalCode(
      string apiClientId, string sessionId, string[] selectedScopes,
      out string code, out string message
    );

    TokenIssuingResult RetrieveTokenByCode(
      string clientId, string clientSecret, string code
    );

    bool TryValidateApiClient(
      string apiClientId,
      string apiCallerHost,
      string redirectUri,
      out string message
    );

    TokenIssuingResult CreateFollowUpToken(
      string refreshToken
    );

  }

  /// <summary>
  /// Conform to https://www.rfc-editor.org/rfc/rfc6749#section-5.1
  /// </summary>
  public class TokenIssuingResult {

    public string access_token { get; set; }
    public string scope { get; set; }
    public string token_type { get; set; }

    /// <summary>
    /// seconds until expiration
    /// </summary>
    public int expires_in { get; set; }

    public string id_token { get; set; }
    public string refresh_token { get; set; }
    public string error { get; set; }
    public string error_description { get; set; }

    public override string ToString() {
      StringBuilder sb = new StringBuilder(300);
      sb.Append("access_token=");
      sb.Append(access_token);

      if (!string.IsNullOrWhiteSpace(scope)) {
        sb.Append("&scope=");
        sb.Append(scope);
      }
      if (!string.IsNullOrWhiteSpace(token_type)) {
        sb.Append("&token_type=");
        sb.Append(token_type);
      }
      if (expires_in > 0) {
        sb.Append("&expires_in=");
        sb.Append(expires_in.ToString());
      }
      if (!string.IsNullOrWhiteSpace(id_token)) {
        sb.Append("&id_token=");
        sb.Append(id_token);
      }
      if (!string.IsNullOrWhiteSpace(refresh_token)) {
        sb.Append("&refresh_token=");
        sb.Append(refresh_token);
      }
      if (!string.IsNullOrWhiteSpace(error)) {
        sb.Append("&error=");
        sb.Append(error);
      }
      if (!string.IsNullOrWhiteSpace(error_description)) {
        sb.Append("&error_description=");
        sb.Append(error_description);
      }
      return sb.ToString();
    }
  }

  /// <summary>
  /// as defined by https://www.rfc-editor.org/rfc/rfc7662 2.2
  /// </summary>
  public class OAuthTokenIntrospectionResult {

    /// <summary>
    ///  REQUIRED. Boolean indicator of whether or not the presented token
    ///  is currently active. The specifics of a token's "active" state
    ///  will vary depending on the implementation of the authorization
    ///  server and the information it keeps about its tokens, but a "true"
    ///  value return for the "active" property will generally indicate
    ///  that a given token has been issued by this authorization server,
    ///  has not been revoked by the resource owner, and is within its
    ///  given time window of validity (e.g., after its issuance time and
    ///  before its expiration time)
    /// </summary>
    [Required]
    public bool active { get; set; }

    /*
    /// <summary>
    /// OPTIONAL. Type of the token as defined in Section 5.1 of OAuth 2.0 [RFC6749]
    /// </summary>
    public string token_type { get; set; } = "";
    */

    /*
    /// <summary>
    ///  OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token
    /// </summary>
    public string client_id { get; set; } = "";
    */

    /// <summary>
    ///  OPTIONAL. Human-readable identifier for the resource owner who authorized this token
    /// </summary>
    public string username { get; set; } = "";

    /// <summary>
    ///  OPTIONAL. A JSON string containing a space-separated list of
    ///  scopes associated with this token, in the format described in
    ///  Section 3.3 of OAuth 2.0 [RFC6749]
    /// </summary>
    public string scope { get; set; } = "";

    /// <summary>
    ///  OPTIONAL. Integer timestamp, measured in the number of seconds
    ///  since January 1 1970 UTC, indicating when this token will expire,
    ///  as defined in JWT[RFC7519]
    /// </summary>
    public long exp { get; set; } = 0;

    /// <summary>
    ///  OPTIONAL. Integer timestamp, measured in the number of seconds
    ///  since January 1 1970 UTC, indicating when this token was
    ///  originally issued, as defined in JWT[RFC7519]
    /// </summary>
    public long iat { get; set; } = 0;

    /*
    /// <summary>
    ///  OPTIONAL. Integer timestamp, measured in the number of seconds
    ///  since January 1 1970 UTC, indicating when this token is not to be
    ///  used before, as defined in JWT[RFC7519]
    /// </summary>
    public long nbf { get; set; } = 0;
    */

    /// <summary>
    ///  OPTIONAL. Subject of the token, as defined in JWT[RFC7519].
    ///  Usually a machine-readable identifier of the resource owner who authorized this token
    /// </summary>
    public string sub { get; set; } = "";

    /// <summary>
    ///  OPTIONAL. Service-specific string identifier or list of string
    ///  identifiers representing the intended audience for this token,
    ///  as defined in JWT[RFC7519]
    /// </summary>
    public string aud { get; set; } = "";

    /// <summary>
    ///  OPTIONAL. String representing the issuer of this token, as defined in JWT[RFC7519]
    /// </summary>
    public string iss { get; set; } = "";

    /*
    /// <summary>
    ///  OPTIONAL. String identifier for the token, as defined in JWT [RFC7519]
    /// </summary>
    public string jti { get; set; } = "";
    */

    /*
    public string error { get; set; }
    public string error_description { get; set; }
    */

  }

  public class ScopeDescriptor {
    public string Expression { get; set; }
    public string Label { get; set; }
    public bool Selected { get; set; }
    public bool ReadOnly { get; set; }
    public bool Invisible { get; set; }
  }

  public static class ScopeDescriptorExtensions {

    public static string[] ToStringArray(this ScopeDescriptor[] scopes) {
      return scopes.Where((s) => s.Selected).Select((s) => s.Expression).ToArray();
    }

  }

  public class EnvironmentUiCustomizing {
    public string AuthPageTitle { get; set; } = "OAuth Logon";
    public string AuthPageLogonText { get; set; } = "Please enter your credentials:";
    public string AuthPageLogoImage { get; set; } = "";
    public string AuthPageBgColor { get; set; } = "#0ca3d2";
    public string PortalUrl { get; set; } = "";
    public string LegalUrl { get; set; } = "";
  }

}
