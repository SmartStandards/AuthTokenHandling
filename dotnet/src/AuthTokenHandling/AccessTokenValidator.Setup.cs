using System;
using System.Collections.Generic;
using System.Reflection;
using static Security.AccessTokenHandling.AccessTokenValidator;

namespace Security.AccessTokenHandling {

  partial class AccessTokenValidator {

    /// <summary>
    /// method to retrieve the IAccessTokenIntrospector
    /// that should be used to validate the token. NOTE: this method will be called for EACH request,
    /// so that you MUST NOT provide a NEW instance on each call (should be some kind of singleton)!
    /// The method can also return null, which represents the semantic, that the token issuer (=origin) is unknown/not trusted.
    /// </summary>
    /// <param name="tokenSourceIdentifier">
    /// the tokenSource which was detected by the IAuthRequirementsProvider
    /// WARNING: can be NULL, if were receiving an token which is not requried!
    /// </param>
    /// <param name="contractType">The contract type</param>
    /// <param name="targetContractMethod">the api method, which the client is trying to invoke</param>
    /// <param name="callingMachine">the client machine (name or IP-address), which has initiated the service-request</param>
    /// <param name="tryReadJwtIssuerMethod">
    /// Can be called to retrieve the issuer from a JWT.
    /// Note that this method should only be called if the tokens are in JWT format AND this information
    /// is really required for selecting the correct introspector!
    /// If the token is not a JWT, null will be returned!
    /// </param>
    /// <returns>
    /// null, if the token issuer (=origin) is unknown/not trusted
    /// </returns>
    public delegate IAccessTokenIntrospector IntrospectorLookupMethod(
      string tokenSourceIdentifier,
      Type contractType,
      MethodInfo targetContractMethod,
      string callingMachine,
      Func<string> tryReadJwtIssuerMethod
    );

    /// <summary>
    /// </summary>
    /// <param name="subject">the subject string as delivered by the introspector (content of the 'sub'-claim)</param>
    /// <param name="permittedScopes">scopes to extend/modify/clear</param>
    public delegate void PermittedScopesVisitorMethod(string subject, List<string> permittedScopes);

    public delegate void RawTokenExposalMethod(string token, MethodInfo targetContractMethod, string subject, string[] permittedScopes);

    /// <summary>
    /// </summary>
    /// <param name="targetContractMethod"></param>
    /// <param name="callingMachine"></param>
    /// <param name="outcome"></param>
    /// <param name="discoveredSubjectIdentity"></param>
    /// <param name="permittedScopes"></param>
    /// <param name="requiredScopes"></param>
    /// <param name="fromCache"></param>
    /// <param name="detailedReason">null, when outcome==AccessGranted</param>
    public delegate void AuditingHook(
      MethodInfo targetContractMethod,
      string callingMachine,
      ValidationOutcome outcome,
      string discoveredSubjectIdentity,
      string[] permittedScopes,
      string[] requiredScopes,
      bool fromCache,
      string detailedReason
    );

    //public enum TokenProcessingOutcome {
    //  TokenProvidedInvalid = -3,
    //  TokenProvidedFromBadOrigin = -2,
    //  NoTokenProvided = 0,
    //  TokenProcessed = 1,
    //}

    public enum ValidationOutcome {

      /// <summary>
      /// the introspector returned isActive=false, which can be caused by some of the following reasons:
      /// 1. the token could not be readed (corrupt or wrong technical format) /
      /// 2. the tokken signature is invalid /
      /// 3. the token is expired or has be revoked /
      /// 4. there are no privileges to the corresponding subject/issuer/audience to access this api anyway
      /// </summary>
      AccessDeniedTokenInvalid = -3,

      /// <summary>
      /// the configured introspectorSelector (HOOK) returned null to indicate,
      /// that the token issuer (=origin) is unknown/not trusted. 
      /// </summary>
      AccessDeniedTokenFromBadOrigin = -2,

      /// <summary>
      /// there was no token provided AND anonymous access was not configured (no anonymousSubjectName is set)
      /// </summary>
      AccessDeniedTokenRequired = -1,

      /// <summary>
      /// one ore more of the requiredScopes are missing within the permittedScopes 
      /// (comming from tokenintrospection and/or scopeHook)
      /// NOTE: this is also affected by the configured apiPermissionPrefix
      /// </summary>
      AccessDeniedMissingPrivileges = 0,

      AccessGranted = 1
    }

    /// <summary>
    /// Configures the IAccessTokenIntrospector which is used when the AuthTokenSourceAttribute and 
    /// optionally the RequiredApiPermissionAttribute is evaluated for a contract.
    /// The returned "scope"-Claim needs to match with ALL of the
    /// "requiredApiPermissions" (passed to the RequiredApiPermissionAttribute-Constructor)
    /// </summary>
    /// <param name="introspector">
    /// IAccessTokenIntrospector that should be used to validate the token.
    /// </param>
    /// <param name="configurationMethod"> several options for customizing the behaviour </param>
    public static void ConfigureTokenValidation(
      IAccessTokenIntrospector introspector,
      Action<TokenIntrospectionConfigurator> configurationMethod = null
    ) {
      if (introspector == null) {
        throw new Exception($"{nameof(introspector)} must not be null!");
      }
      _RequirementsProvider = new AttributeBasedAuthRequirementsProvider("default");
      _IntrospectorSelector = (tokenSource, contractType, calledMethod, callingMachine, tryReadJwtIssuerMethod) => introspector;
      if (configurationMethod != null) {
        configurationMethod.Invoke(new TokenIntrospectionConfigurator());
      }
    }

    /// <summary>
    /// Configures the IAccessTokenIntrospector to use an 'IAuthRequirementsProvider' to
    /// evaluate the necessity of any token validation and/ore additional requirements like
    /// "requiredApiPermissions".
    /// </summary>
    /// <param name="requirementsProvider">
    /// Specifies 'IAuthRequirementsProvider' to
    /// evaluate the necessity of any token validation and/ore additional requirements like
    /// "requiredApiPermissions". The "scope"-Claim, returned by the corresponding introspector
    /// needs to match with ALL of these "requiredApiPermissions" 
    /// </param>
    /// <param name="introspectorLookupMethod">
    /// method to retrieve the IAccessTokenIntrospector
    /// that should be used to validate the token. NOTE: this method will be called for EACH request,
    /// so that you MUST NOT provide a NEW instance on each call (should be some kind of singleton)!
    /// The method can also return null, which represents the semantic, that the token issuer (=origin) is unknown/not trusted.
    /// </param>
    /// <param name="configurationMethod"> several options for customizing the behaviour </param>
    public static void ConfigureTokenValidation(
      IAuthRequirementsProvider requirementsProvider,
      IntrospectorLookupMethod introspectorLookupMethod, 
      Action<TokenIntrospectionConfigurator> configurationMethod = null
    ) {
      if (requirementsProvider == null) {
        throw new Exception($"{nameof(requirementsProvider)} must not be null!");
      }
      if (introspectorLookupMethod == null) {
        throw new Exception($"{nameof(introspectorLookupMethod)} must not be null!");
      }
      _RequirementsProvider = requirementsProvider;
      _IntrospectorSelector = introspectorLookupMethod;
      if (configurationMethod != null) {
        configurationMethod.Invoke(new TokenIntrospectionConfigurator());
      }
    }

    /// <summary>
    /// Configures the token validation to be driven completely by the 'AccessTokenManager' (recommended for new setups):
    /// the token sources are resolved via the manager's resolution chain (issuer mapping, AuthTokenSourceAttribute,
    /// API group name, contract name, 'default'), several token sources are tried in mapping order, validated tokens are
    /// pushed into the manager's register, and the requirements (token required? which scopes?) are taken from the
    /// manager ('MapAnonymous', 'RequireScope') plus the legacy 'RequiredApiPermissionAttribute'.
    /// Without an anonymous mapping a token is ALWAYS required (fail closed).
    /// </summary>
    /// <param name="configurationMethod"> several options for customizing the behaviour </param>
    public static void ConfigureTokenValidationViaAccessTokenManager(
      Action<TokenIntrospectionConfigurator> configurationMethod = null
    ) {
      _RequirementsProvider = null;
      _IntrospectorSelector = AccessTokenManager.LookupForIntrospector;
      if (configurationMethod != null) {
        configurationMethod.Invoke(new TokenIntrospectionConfigurator());
      }
    }

    public class TokenIntrospectionConfigurator {

      /// <summary>
      /// Can be used to:
      /// extend/modify/clear the scopes returned by the introspector before evaluation AND/OR
      /// validate against subject black-/white-lists AND/OR
      /// to distribute them for example to a MAC context.
      /// </summary>
      /// <param name="visitor"></param>
      public void UseScopeVisitor(PermittedScopesVisitorMethod visitor) {
        _PermittedScopesVisitorMethod = visitor;
      }

      /// <summary> This hook will only be invoked AFTER the VALIDATION has been passed successfully!</summary>
      /// <param name="hook"></param>
      public void UseRawTokenExposal(RawTokenExposalMethod hook) {
        _RawTokenExposalMethod = hook;
      }

      /// <summary> This hook will only invoked ALWAYS (also for invalid tokens)</summary>
      /// <param name="hook"></param>
      public void UseAuditingHook(AuditingHook hook) {
        _AuditingHook = hook;
      }

      /// <summary>
      /// if set, TOKENS WILL BECOME OPTIONAL and the provided 'ScopeVisitor' will be
      /// called in this case passing the given anonymousSubjectName to it.
      /// The hook can provide default scopes which should be permitted for the caller. 
      /// </summary>
      /// <param name="anonymousSubjectName"></param>
      public void EnableAnonymousSubject(string anonymousSubjectName) {
        _AnonymousSubjectName = anonymousSubjectName;
      }

      /// <summary>
      /// a prefix for the "requiredScopes", passed to the TryValidateTokenAndEvaluateScopes-Method.
      /// Example: TryValidateTokenAndEvaluateScopes(,,,{"UserAdministration"}) in combination with the apiPermissionPrefix "API:" (which is default)
      /// will require that the "scope"-claim of the token needs to contain the expression "API:UserAdministration"
      /// </summary>
      /// <param name="prefix"></param>
      public void ChangeScopePrefixForApiPermissions(string prefix) {
        _ApiPermissionPrefix = prefix;
      }

      /// <summary>
      /// sets, how many minutes the introspection outcome should be cached before it will be re-evaluated
      /// </summary>
      /// <param name="lifetimeMinutes"></param>
      public void ChangeCachingLifetime(int lifetimeMinutes) {
        _IntrospectionResultCachingMinutes = lifetimeMinutes;
      }

    }

    /// <summary>
    /// Configures the (OPT-IN) builder for the challenge headers of authentication-required HTTP rejections
    /// (e.g. 'WWW-Authenticate: Bearer resource_metadata="...", scope="..."'). It is invoked for 401 only (never for 403)
    /// with the status code and the effective required scopes (already prefixed, exactly as checked against the token).
    /// 'AddWellKnownOAuthProtectedResourceEndpoint(...)' (MvcSupport) wires it up automatically, unless a builder was
    /// already configured by the host. Header values may contain the placeholder '{RequestBaseUrl}' (see
    /// 'TryValidateHttpAuthHeader').
    /// </summary>
    /// <param name="headerBuilder">The header builder, or null to disable challenge headers.</param>
    public static void ConfigureChallengeHeaders(
      Func<int, string[], KeyValuePair<string, string>[]> headerBuilder
    ) {
      lock (_ChallengeHeaderBuilderLock) {
        _ChallengeHeaderBuilder = headerBuilder;
      }
    }

    /// <summary>
    /// Disables the challenge headers for authentication-required HTTP rejections.
    /// </summary>
    public static void ClearChallengeHeaders() {
      ConfigureChallengeHeaders(null);
    }

    /// <summary>
    /// Returns true, if a builder for challenge headers is configured.
    /// </summary>
    public static bool IsChallengeHeaderBuilderConfigured {
      get {
        lock (_ChallengeHeaderBuilderLock) {
          return _ChallengeHeaderBuilder != null;
        }
      }
    }

    /// <summary>
    /// Invokes the configured challenge header builder (returns an empty array if none is configured).
    /// </summary>
    private static KeyValuePair<string, string>[] BuildChallengeHeaders(int statusCode, string[] requiredScopes) {

      Func<int, string[], KeyValuePair<string, string>[]> headerBuilder;
      lock (_ChallengeHeaderBuilderLock) {
        headerBuilder = _ChallengeHeaderBuilder;
      }

      if (headerBuilder == null) {
        return new KeyValuePair<string, string>[] { };
      }
      if (requiredScopes == null) {
        requiredScopes = new string[] { };
      }

      KeyValuePair<string, string>[] headers = headerBuilder.Invoke(statusCode, requiredScopes);
      if (headers == null) {
        return new KeyValuePair<string, string>[] { };
      }
      return headers;
    }

    private static IAuthRequirementsProvider _RequirementsProvider;
    private static IntrospectorLookupMethod _IntrospectorSelector;
    private static PermittedScopesVisitorMethod _PermittedScopesVisitorMethod = null;
    private static AuditingHook _AuditingHook = null;
    private static RawTokenExposalMethod _RawTokenExposalMethod = null;
    private static Func<int, string[], KeyValuePair<string, string>[]> _ChallengeHeaderBuilder = null;
    private static readonly object _ChallengeHeaderBuilderLock = new object();

    private static string _AnonymousSubjectName = null;
    private static string _ApiPermissionPrefix = "API:";
    private static int _IntrospectionResultCachingMinutes = 2;

    /// <summary>
    /// The currently configured API permission prefix (shared with the AccessTokenManager to keep the prefix symmetric).
    /// </summary>
    internal static string ApiPermissionPrefix {
      get {
        if (_ApiPermissionPrefix == null) {
          return string.Empty;
        }
        return _ApiPermissionPrefix;
      }
    }

    /// <summary>
    /// The currently configured (legacy) requirements provider (null, if the validator was not configured yet).
    /// </summary>
    internal static IAuthRequirementsProvider ConfiguredRequirementsProvider {
      get {
        return _RequirementsProvider;
      }
    }

  }

}
