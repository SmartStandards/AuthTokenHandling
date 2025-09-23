using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling.OAuth {

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

    /// <summary>
    ///  OPTIONAL. String identifier for the token, as defined in JWT [RFC7519]
    /// </summary>
    public string jti { get; set; } = "";

    /*
    public string error { get; set; }
    public string error_description { get; set; }
    */

  }

}
