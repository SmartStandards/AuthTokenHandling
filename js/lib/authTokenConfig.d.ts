export declare class AuthTokenConfig {
    /**
     * <NAME_OF_THE_STRATEGY>
     * RAW-INPUT
     * HTTP-GET
     * LOCAL_BASICAUTH_GENERATION
     * LOCAL_JWT_GENERATION
     * OAUTH_CIBA_CODEGRAND
     */
    issueMode: "RAW-INPUT" | "HTTP-GET" | "LOCAL_BASICAUTH_GENERATION" | "LOCAL_JWT_GENERATION" | "OAUTH_CIBA_CODEGRAND";
    /**
     * when using issue mode *HTTP-GET*, then it could be: ```"assets/demoAccessToken.txt"```
     * or when using issue mode *OAUTH_CIBA_CODEGRAND*, then it could be: ```"https://theOAuthServer/token"```.
     * The fixpoint when resolving a relative URL provided for this value is the
     * (portfolio.json)-url where the current PortfolioDescription was loaded from.
     */
    retrieveEndpointUrl: string;
    /**
     * basic %232432-23452-234234234%
     */
    retrieveEndpointAuthorization: string | null;
    /**
     *
     */
    localLogonNameToLower?: boolean;
    /**
     * "NEVER" | "OPT-IN" | "OPT-OUT" | "ALWAYS"
     * (default, if not provided: "OPT-IN")
     */
    localLogonNamePersistation?: "NEVER" | "OPT-IN" | "OPT-OUT" | "ALWAYS";
    /**
     * LOCAL_JWT_GENERATION
     * Regular expression to validate a username pattern
     */
    localLogonNameSyntax: string | null;
    /**
     * LOCAL_JWT_GENERATION
     * Employee number
     */
    localLogonNameInputLabel: string | null;
    /**
     * LOCAL_JWT_GENERATION
     * Portal password
     */
    localLogonPassInputLabel: string | null;
    /**
     * LOCAL_JWT_GENERATION
     */
    localLogonSaltDisplayLabel: string | null;
    /**
     * LOCAL_JWT_GENERATION
     */
    jwtExpMinutes: number;
    /**
     *
     */
    jwtSelfSignKey: string | null;
    /**
     * default SHA265
     */
    jwtSelfSignAlg: string | null;
    /**
     * OAUTH_CIBA_CODEGRAND
     */
    clientId: string | null;
    /**
     * OAUTH_CIBA_CODEGRAND
     */
    clientSecret: string | null;
    /**
     * OAUTH_CIBA_CODEGRAND
     * "https://theOAuthServer/authorize"
     */
    authEndpointUrl: string | null;
    /**
     *
     */
    additionalAuthArgs: {
        [argName: string]: [value: string];
    } | null;
    /**
     *
     */
    additionalRetrieveArgs: {
        [argName: string]: [value: string];
    } | null;
    /**
     *
     */
    retrieveViaGet: boolean;
    /**
     * this can be set to true to inform about the fact, that the
     * oauth-server will reject any logon within a iframe or is just not able
     * to handle its session-cookies correctly.
     * based on this, the ushell will skip the convenience of serving the logon
     * page within an iframe (instead of this the user will need to click on a hyperlink)
     */
    authEndpointRejectsIframe: boolean;
    /**
     *  IMPLICIT_WHEN_USED
     *  LOCAL_JWT_VALIDATION
     *  OAUTH_INTROSPECTION_ENDPOINT
     *  GITHUB_VALIDATION_ENDPOINT
     */
    validationMode: "IMPLICIT_WHEN_USED" | "LOCAL_JWT_VALIDATION" | "OAUTH_INTROSPECTION_ENDPOINT" | "GITHUB_VALIDATION_ENDPOINT";
    /**
     *
     */
    validationOutcomeCacheMins: number;
    /**
     * LOCAL_JWT_VALIDATION
     */
    jwtValidationKey?: string | null;
    /**
     * LOCAL_JWT_VALIDATION
     */
    jwtAlg?: string | null;
    /**
     *  not compatible to IMPLICIT_WHEN_USED
     */
    claimValidationIgnoresCasing: boolean;
    /**
     * Only requrired, when using a service endpoint to validate the token.
     * "https://theOAuthServer/introspect"
     */
    validationEndpointUrl?: string | null;
    /**
     * Only available, when using a service endpoint to validate the token.
     * Specifies content for thethe HTTP-Authorization header like this:
     * ```"basic %232432-23452-234234234%"``` or ```"bearer %232432-23452-234234234%"```
     * where any *tokenSourceUid* can be used as placeholder.
     */
    validationEndpointAuthorization?: string | null;
    /**
     * Claims, used for local JWT issuing and/or token validation.
     * Sample:
     * ```{ "sub":"user-%logonName%", "aud": "CompanyX", "scope":"foo bar:%tenant% baz" }```
     */
    claims?: {
        [claim: string]: [value: string];
    } | null;
}
//# sourceMappingURL=authTokenConfig.d.ts.map