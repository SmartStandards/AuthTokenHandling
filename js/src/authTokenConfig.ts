
export class AuthTokenConfig {

  // ISSUEING /////////////////////////////////////////////////////////////////////

  /**
   * <NAME_OF_THE_STRATEGY>
   * RAW-INPUT
   * HTTP-GET
   * LOCAL_BASICAUTH_GENERATION
   * LOCAL_JWT_GENERATION
   * OAUTH_CIBA_CODEGRAND
   * OAUTH_CIBA_CODEGRAND_HTTPGETONLY < use url-params instead of post-body to avoid CORS problems
   */
  public issueMode: "RAW-INPUT" | "HTTP-GET" | "LOCAL_BASICAUTH_GENERATION" | "LOCAL_JWT_GENERATION" | "OAUTH_CIBA_CODEGRAND" | "OAUTH_CIBA_CODEGRAND_HTTPGETONLY"= "RAW-INPUT";

  /**
   * when using issue mode *HTTP-GET*, then it could be: ```"assets/demoAccessToken.txt"```
   * or when using issue mode *OAUTH_CIBA_CODEGRAND*, then it could be: ```"https://theOAuthServer/token"```.
   * The fixpoint when resolving a relative URL provided for this value is the
   * (portfolio.json)-url where the current PortfolioDescription was loaded from.
   */
  public retrieveEndpointUrl: string = "";

  /**
   * basic %232432-23452-234234234%
   */
  public retrieveEndpointAuthorization: string | null = null;

  /**
   * 
   */
  public localLogonNameToLower?: boolean = false;

  /**
   * "NEVER" | "OPT-IN" | "OPT-OUT" | "ALWAYS"
   * (default, if not provided: "OPT-IN")
   */
  public localLogonNamePersistation?: "NEVER" | "OPT-IN" | "OPT-OUT" | "ALWAYS";

  /**
   * LOCAL_JWT_GENERATION
   * Regular expression to validate a username pattern
   */
  public localLogonNameSyntax: string | null = null;

  /**
   * LOCAL_JWT_GENERATION
   * Employee number
   */
  public localLogonNameInputLabel: string | null = "Username";

  /**
   * LOCAL_JWT_GENERATION
   * Portal password
   */
  public localLogonPassInputLabel: string | null = "Password";

  /**
   * LOCAL_JWT_GENERATION
   */
  public localLogonSaltDisplayLabel: string | null = null;

  /**
   * LOCAL_JWT_GENERATION
   */
  public jwtExpMinutes: number = 1440;

  /**
   * 
   */
  public jwtSelfSignKey: string | null = null;

  /**
   * default SHA265
   */
  public jwtSelfSignAlg: string | null = null;

  /**
   * OAUTH_CIBA_CODEGRAND
   */
  public clientId: string | null = null;
  /**
   * OAUTH_CIBA_CODEGRAND
   */
  public clientSecret: string | null = null;

  /**
   * OAUTH_CIBA_CODEGRAND
   * "https://theOAuthServer/authorize"
   */
  public authEndpointUrl: string | null = null;

  /**
   * 
   */
  public additionalAuthArgs: { [argName: string]: [value: string] } | null = null;

  /**
   * 
   */
  public additionalRetrieveArgs: { [argName: string]: [value: string] } | null = null;

  /**
   * this can be set to true to inform about the fact, that the
   * oauth-server will reject any logon within a iframe or is just not able
   * to handle its session-cookies correctly.
   * based on this, the ushell will skip the convenience of serving the logon
   * page within an iframe (instead of this the user will need to click on a hyperlink) 
   */
  public authEndpointRejectsIframe: boolean = false;

  // VALIDATION /////////////////////////////////////////////////////////////////////

  /**
   *  IMPLICIT_WHEN_USED
   *  LOCAL_JWT_VALIDATION
   *  OAUTH_INTROSPECTION_ENDPOINT
   *  OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY < use url-params instead of post-body to avoid CORS problems
   *  GITHUB_VALIDATION_ENDPOINT
   */
  public validationMode: "IMPLICIT_WHEN_USED" | "LOCAL_JWT_VALIDATION" | "OAUTH_INTROSPECTION_ENDPOINT" | "OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY" | "GITHUB_VALIDATION_ENDPOINT" = "IMPLICIT_WHEN_USED";

  /**
   * 
   */
  public validationOutcomeCacheMins: number = 15;

  /**
   * LOCAL_JWT_VALIDATION
   */
  public jwtValidationKey?: string | null;

  /**
   *  not compatible to IMPLICIT_WHEN_USED
   */
  public claimValidationIgnoresCasing: boolean = true;

  /**
   * Only requrired, when using a service endpoint to validate the token.
   * "https://theOAuthServer/introspect"
   */
  public validationEndpointUrl?: string | null;

  /**
   * Only available, when using a service endpoint to validate the token.
   * Specifies content for thethe HTTP-Authorization header like this:
   * ```"basic %232432-23452-234234234%"``` or ```"bearer %232432-23452-234234234%"```
   * where any *tokenSourceUid* can be used as placeholder.
   */
  public validationEndpointAuthorization?: string | null;

  // CLAIMS /////////////////////////////////////////////////////////////////////

  /**
   * Claims, used for local JWT issuing and/or token validation.
   * Sample:
   * ```{ "sub":"user-%logonName%", "aud": "CompanyX", "scope":"foo bar:%tenant% baz" }```
   */
  public claims?: { [claim: string]: [value: string] } | null;

}
