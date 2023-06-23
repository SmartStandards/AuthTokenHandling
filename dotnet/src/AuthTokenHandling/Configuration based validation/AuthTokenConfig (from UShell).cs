using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling {

  public class AuthTokenConfig {

    #region " ISSUEING "

    /// <summary>
    /// Name of the Straregy:
    /// RAW-INPUT
    /// HTTP-GET
    /// LOCAL_BASICAUTH_GENERATION
    /// LOCAL_JWT_GENERATION
    /// OAUTH_CIBA_CODEGRAND
    /// OAUTH_CIBA_CODEGRAND_HTTPGETONLY - use url-params instead of post-body to avoid CORS problems
    /// </summary>
    public string IssueMode { get; set; } = "RAW-INPUT";

    /// <summary>
    /// when using issue mode HTTP-GET, then it could be: "assets/demoAccessToken.txt"
    /// or when using issue mode OAUTH_CIBA_CODEGRAND, then it could be: "https://theOAuthServer/token".
    /// The fixpoint when resolving a relative URL provided for this value is the
    /// (portfolio.json)-url where the current PortfolioDescription was loaded from.
    /// </summary>
    public string RetrieveEndpointUrl { get; set; } = "";

    /// <summary>
    /// for Example "basic %232432-23452-234234234%"
    /// </summary>
    public string RetrieveEndpointAuthorization { get; set; } = null;

    public bool LocalLogonNameToLower { get; set; } = false;

    /// <summary>
    /// "NEVER" | "OPT-IN" | "OPT-OUT" | "ALWAYS"
    /// (default, if not provided: "OPT-IN")
    /// </summary>
    public string LocalLogonNamePersistation { get; set; } = "OPT-IN";

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// Regular expression to validate a username pattern
    /// </summary>
    public string LocalLogonNameSyntax { get; set; } = null;

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// for example a Employee number
    /// </summary>
    public string LocalLogonNameInputLabel { get; set; } = "Username";

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// for example a Portal password
    /// </summary>
    public string LocalLogonPassInputLabel { get; set; } = "Password";

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// </summary>
    public string LocalLogonSaltDisplayLabel { get; set; } = null;

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// </summary>
    public int JwtExpMinutes { get; set; } = 1440;

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// (the given string also be a JSON-Strucutre representing a 'JWK')
    /// </summary>
    public string JwtSelfSignKey { get; set; } = null;

    /// <summary>
    /// only valid for: LOCAL_JWT_GENERATION
    /// (default: "SHA265")
    /// </summary>
    public string JwtSelfSignAlg { get; set; } = "SHA265";

    /// <summary>
    /// only valid for: OAUTH_CIBA_CODEGRAND
    /// </summary>
    public string ClientId { get; set; } = null;

    /// <summary>
    /// only valid for: OAUTH_CIBA_CODEGRAND
    /// </summary>
    public string ClientSecret { get; set; } = null;

    /// <summary>
    /// only valid for: OAUTH_CIBA_CODEGRAND
    /// for example "https://theOAuthServer/authorize"
    /// </summary>
    public string AuthEndpointUrl { get; set; } = null;

    /// <summary>
    /// will be added the the request when accessing the oauth page
    /// </summary>
    public Dictionary<string, string> AdditionalAuthArgs { get; set; } = null;

    /// <summary>
    /// will be added the the request when retrieving the token from the oauth server
    /// </summary>
    public Dictionary<string, string> AdditionalRetrieveArgs { get; set; } = null;

    ///// <summary>
    ///// use HTTP-GET instead of -POST when retrieving the token
    ///// (this is not compliant with the OAUTH-2 standard but can help against CORS problems!)
    ///// </summary>
    //public bool RetrieveViaGet { get; set; } = false;

    /// <summary>
    /// this can be set to true to inform about the fact, that the
    /// oauth-server will reject any logon within a iframe or is just not able
    /// to handle its session-cookies correctly.
    /// based on this, the ushell will skip the convenience of serving the logon
    /// page within an iframe (instead of this the user will need to click on a hyperlink) 
    /// </summary>
    public bool AuthEndpointRejectsIframe { get; set; } = false;

    #endregion

    #region " VALIDATION "

    /// <summary>
    /// IMPLICIT_WHEN_USED
    /// LOCAL_JWT_VALIDATION
    /// OAUTH_INTROSPECTION_ENDPOINT
    /// OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY - use url-params instead of post-body to avoid CORS problems
    /// GITHUB_VALIDATION_ENDPOINT
    /// </summary>
    public string ValidationMode { get; set; } = "IMPLICIT_WHEN_USED";

    /// <summary>
    /// minutes to cache validation outcomes
    /// (default: 2min)
    /// </summary>
    public int ValidationOutcomeCacheMins { get; set; } = 2;

    /// <summary>
    /// LOCAL_JWT_VALIDATION
    /// (the given string also be a JSON-Strucutre representing a 'JWK')
    /// </summary>
    public string JwtValidationKey { get; set; } = null;

    /// <summary>
    /// not compatible to IMPLICIT_WHEN_USED
    /// </summary>
    public bool ClaimValidationIgnoresCasing { get; set; } = true;

    /// <summary>
    /// Only requrired, when using a service endpoint to validate the token.
    /// "https://theOAuthServer/introspect"
    /// </summary>
    public string ValidationEndpointUrl { get; set; } = null;

    /// <summary>
    /// Only available, when using a service endpoint to validate the token.
    /// Specifies content for thethe HTTP-Authorization header like this:
    /// "basic %232432-23452-234234234%" or "bearer %232432-23452-234234234%"
    /// where any *tokenSourceUid* can be used as placeholder.
    /// </summary>
    public string validationEndpointAuthorization { get; set; } = null;

    #endregion

    // CLAIMS /////////////////////////////////////////////////////////////////////

    /// <summary>
    /// Claims, used for JWT self issuing (local only) and/or token validation (local or endpoint-based).
    /// Sample:
    /// { "sub":"user-%logonName%", "aud": "CompanyX", "scope":"foo bar:%tenant% baz" }
    /// </summary>
    public Dictionary<string, string> Claims { get; set; } = null;

  }

}