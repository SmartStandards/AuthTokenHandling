"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthTokenConfig = void 0;
class AuthTokenConfig {
    constructor() {
        // ISSUEING /////////////////////////////////////////////////////////////////////
        /**
         * <NAME_OF_THE_STRATEGY>
         * RAW-INPUT
         * HTTP-GET
         * LOCAL_BASICAUTH_GENERATION
         * LOCAL_JWT_GENERATION
         * OAUTH_CIBA_CODEGRAND
         */
        this.issueMode = "RAW-INPUT";
        /**
         * when using issue mode *HTTP-GET*, then it could be: ```"assets/demoAccessToken.txt"```
         * or when using issue mode *OAUTH_CIBA_CODEGRAND*, then it could be: ```"https://theOAuthServer/token"```.
         * The fixpoint when resolving a relative URL provided for this value is the
         * (portfolio.json)-url where the current PortfolioDescription was loaded from.
         */
        this.retrieveEndpointUrl = "";
        /**
         * basic %232432-23452-234234234%
         */
        this.retrieveEndpointAuthorization = null;
        /**
         *
         */
        this.localLogonNameToLower = false;
        /**
         * LOCAL_JWT_GENERATION
         * Regular expression to validate a username pattern
         */
        this.localLogonNameSyntax = null;
        /**
         * LOCAL_JWT_GENERATION
         * Employee number
         */
        this.localLogonNameInputLabel = "Username";
        /**
         * LOCAL_JWT_GENERATION
         * Portal password
         */
        this.localLogonPassInputLabel = "Password";
        /**
         * LOCAL_JWT_GENERATION
         */
        this.localLogonSaltDisplayLabel = null;
        /**
         * LOCAL_JWT_GENERATION
         */
        this.jwtExpMinutes = 1440;
        /**
         *
         */
        this.jwtSelfSignKey = null;
        /**
         * default SHA265
         */
        this.jwtSelfSignAlg = null;
        /**
         * OAUTH_CIBA_CODEGRAND
         */
        this.clientId = null;
        /**
         * OAUTH_CIBA_CODEGRAND
         */
        this.clientSecret = null;
        /**
         * OAUTH_CIBA_CODEGRAND
         * "https://theOAuthServer/authorize"
         */
        this.authEndpointUrl = null;
        /**
         *
         */
        this.additionalAuthArgs = null;
        /**
         *
         */
        this.additionalRetrieveArgs = null;
        /**
         *
         */
        this.retrieveViaGet = false;
        /**
         * this can be set to true to inform about the fact, that the
         * oauth-server will reject any logon within a iframe or is just not able
         * to handle its session-cookies correctly.
         * based on this, the ushell will skip the convenience of serving the logon
         * page within an iframe (instead of this the user will need to click on a hyperlink)
         */
        this.authEndpointRejectsIframe = false;
        // VALIDATION /////////////////////////////////////////////////////////////////////
        /**
         *  IMPLICIT_WHEN_USED
         *  LOCAL_JWT_VALIDATION
         *  OAUTH_INTROSPECTION_ENDPOINT
         *  GITHUB_VALIDATION_ENDPOINT
         */
        this.validationMode = "IMPLICIT_WHEN_USED";
        /**
         *
         */
        this.validationOutcomeCacheMins = 15;
        /**
         *  not compatible to IMPLICIT_WHEN_USED
         */
        this.claimValidationIgnoresCasing = true;
    }
}
exports.AuthTokenConfig = AuthTokenConfig;
//# sourceMappingURL=authTokenConfig.js.map