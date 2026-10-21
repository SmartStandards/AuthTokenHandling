using Jose;
using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;

namespace Security.AccessTokenHandling {

  public partial class AccessTokenValidator {

    private AccessTokenValidator() {
    }

    private static List<CacheEntry> _Cache = new List<CacheEntry>();

    private class CacheEntry {
      public string RawToken { get; set; }
      public string CallerHost { get; set; }

      /// <summary>
      /// Resolution context of the entry (API group and - in manager mode - contract), so that a result which was
      /// produced for one logical group is never reused for another one ("" for legacy callers = unchanged behavior).
      /// </summary>
      public string ResolutionKey { get; set; }
      public bool IsActive { get; set; }
      public string InactiveReason { get; set; }
      public string[] PermittedScopes { get; set; }
      public string Subject { get; set; }
      public DateTime CachableUntil { get; set; }

      /// <summary>
      /// The token source which has accepted the token (handed over to the AccessTokenManager on cache hits).
      /// </summary>
      public string MatchedTokenSourceId { get; set; }
    }

    #region " Convenience overloads for UJMW AuthHeaderEvaluator "

    /// <summary>
    /// A convenience method which has a compatible signature to be wired-up as 'UjmwHostConfiguration.AuthHeaderEvaluatorMethod'.
    /// It automatically strips a "Bearer"-Prefix (if existing) and maps the validation-outcomt to an http-return code...
    /// </summary>
    /// <param name="rawAuthHeader"></param>
    /// <param name="contractType"></param>
    /// <param name="calledContractMethod"></param>
    /// <param name="callingMachine"></param>
    /// <param name="httpReturnCode">will only be changed on negative outcome (401/403)</param>
    /// <param name="httpReasonPhrase">a Reason-Phrase which shall be transmitted to the client (low detail!, to reduce attack-surface)</param>
    /// <returns></returns>
    public static bool TryValidateHttpAuthHeader(
      string rawAuthHeader, Type contractType, MethodInfo calledContractMethod, string callingMachine, ref int httpReturnCode, ref string httpReasonPhrase
    ) {
      var noExplicitelyRequiredApiPermissions = new string[] { };
      return TryValidateHttpAuthHeader(
        rawAuthHeader, contractType, calledContractMethod, callingMachine, ref httpReturnCode, ref httpReasonPhrase, noExplicitelyRequiredApiPermissions
      );
    }

    /// <summary>
    /// A convenience method which has a compatible signature to be wired-up as 'UjmwHostConfiguration.AuthHeaderEvaluatorMethod'.
    /// It automatically strips a "Bearer"-Prefix (if existing) and maps the validation-outcomt to an http-return code...
    /// </summary>
    /// <param name="rawAuthHeader"></param>
    /// <param name="contractType"></param>
    /// <param name="calledContractMethod"></param>
    /// <param name="callingMachine"></param>
    /// <param name="httpReturnCode">will only be changed on negative outcome (401/403)</param>
    /// <param name="requiredApiPermissions"></param>
    /// <param name="httpReasonPhrase">a Reason-Phrase which shall be transmitted to the client (low detail!, to reduce attack-surface)</param>
    /// <returns></returns>
    public static bool TryValidateHttpAuthHeader(
      string rawAuthHeader, Type contractType, MethodInfo calledContractMethod, string callingMachine,
      ref int httpReturnCode, ref string httpReasonPhrase,
      params string[] requiredApiPermissions
    ) {

      KeyValuePair<string, string>[] challengeHeaders;
      return TryValidateHttpAuthHeaderCore(
        rawAuthHeader, contractType, calledContractMethod, string.Empty, callingMachine,
        ref httpReturnCode, ref httpReasonPhrase,
        out challengeHeaders,
        requiredApiPermissions
      );

    }

    /// <summary>
    /// A convenience method which has EXACTLY the signature of UJMW's 'AuthHeaderValidationMethod' delegate, so that it
    /// can be wired-up via 'UjmwHostConfiguration.SetAuthHeaderEvaluator(AccessTokenValidator.TryValidateHttpAuthHeader)'
    /// (without any reference to UJMW). It strips a "Bearer"-Prefix (if existing), maps the validation-outcome to an
    /// http-return code and appends the challenge headers (for example 'WWW-Authenticate', see 'ConfigureChallengeHeaders')
    /// to the given 'responseHeaders' (preset headers are kept). On 403 no challenge headers are added.
    /// OFFICIAL CONVENTION: the appended header values may contain the literal placeholder '{RequestBaseUrl}'.
    /// Every HTTP adapter writing these headers MUST replace every occurrence (plain, case-sensitive) with the base URL
    /// of its own request ('scheme://host[:port]' plus path base, without trailing slash).
    /// </summary>
    /// <param name="rawAuthHeader">the raw content of the 'Authorization' header (can be null)</param>
    /// <param name="contractType">the contract type of the called service</param>
    /// <param name="targetContractMethod">the called contract method</param>
    /// <param name="apiGroupName">the API group name (logical name) of the endpoint or "" if not known</param>
    /// <param name="callingMachine">the client machine (name or IP-address)</param>
    /// <param name="httpReturnCode">will only be changed on negative outcome (401/403)</param>
    /// <param name="failedReason">a Reason-Phrase which shall be transmitted to the client (low detail!)</param>
    /// <param name="responseHeaders">
    /// headers to be written by the HTTP adapter (an empty array is passed in, null is tolerated). The values may contain
    /// the placeholder '{RequestBaseUrl}' which MUST be replaced by the adapter (see summary).
    /// </param>
    public static bool TryValidateHttpAuthHeader(
      string rawAuthHeader,
      Type contractType,
      MethodInfo targetContractMethod,
      string apiGroupName,
      string callingMachine,
      ref int httpReturnCode,
      ref string failedReason,
      ref KeyValuePair<string, string>[] responseHeaders
    ) {

      return TryValidateHttpAuthHeader(
        rawAuthHeader, contractType, targetContractMethod, apiGroupName, callingMachine,
        ref httpReturnCode, ref failedReason, ref responseHeaders,
        new string[] { }, null
      );
    }

    /// <summary>
    /// Validates an HTTP Authorization header using the API group name (logical name, "" if not known) and additional
    /// logical names of the call (e.g. authentication scheme or policy names from '[Authorize]'), which take part in the
    /// AccessTokenManager's resolution chain (after the API group name). The additional logical names are ignored when a
    /// legacy 'IAuthRequirementsProvider' is configured (it decides alone).
    /// On 401 the challenge headers (see 'ConfigureChallengeHeaders') are appended to 'responseHeaders' (preset headers
    /// are kept); on 403 no challenge headers are added.
    /// OFFICIAL CONVENTION: the appended header values may contain the literal placeholder '{RequestBaseUrl}', which
    /// MUST be replaced by the HTTP adapter with the base URL of its own request.
    /// </summary>
    public static bool TryValidateHttpAuthHeader(
      string rawAuthHeader, Type contractType, MethodInfo calledContractMethod, string apiGroupName, string callingMachine,
      ref int httpReturnCode, ref string httpReasonPhrase,
      ref KeyValuePair<string, string>[] responseHeaders,
      string[] requiredApiPermissions,
      string[] additionalLogicalNames
    ) {
      if (_RequirementsProvider != null) {
        additionalLogicalNames = null;
      }
      KeyValuePair<string, string>[] challengeHeaders;
      bool accessGranted;
      AccessTokenManager.SetCurrentAdditionalLogicalNames(additionalLogicalNames);
      try {
        accessGranted = TryValidateHttpAuthHeaderCore(
          rawAuthHeader, contractType, calledContractMethod, apiGroupName, callingMachine,
          ref httpReturnCode, ref httpReasonPhrase,
          out challengeHeaders,
          requiredApiPermissions
        );
      }
      finally {
        AccessTokenManager.SetCurrentAdditionalLogicalNames(null);
      }

      List<KeyValuePair<string, string>> headers = new List<KeyValuePair<string, string>>();
      if (responseHeaders != null) {
        headers.AddRange(responseHeaders);
      }
      foreach (KeyValuePair<string, string> header in challengeHeaders) {
        if (!string.IsNullOrWhiteSpace(header.Key)) {
          headers.Add(header);
        }
      }
      responseHeaders = headers.ToArray();

      return accessGranted;
    }

    /// <summary>
    /// true, if a legacy 'IAuthRequirementsProvider' is configured (it alone decides about the requirements).
    /// </summary>
    public static bool IsRequirementsProviderConfigured {
      get {
        return _RequirementsProvider != null;
      }
    }

    /// <summary>
    /// Internal core of all 'TryValidateHttpAuthHeader' overloads (with the additional API group name).
    /// </summary>
    internal static bool TryValidateHttpAuthHeaderCore(
      string rawAuthHeader, Type contractType, MethodInfo calledContractMethod, string apiGroupName, string callingMachine,
      ref int httpReturnCode, ref string httpReasonPhrase,
      out KeyValuePair<string, string>[] challengeHeaders,
      string[] requiredApiPermissions
    ) {

      challengeHeaders = new KeyValuePair<string, string>[] { };

      string rawToken = StripTokenPrefix(rawAuthHeader);

      string invalidReason;
      string[] effectiveRequiredScopes;
      ValidationOutcome outcome = ValidateTokenAndEvaluateScopesCore(
        rawToken, contractType, calledContractMethod, apiGroupName, callingMachine,
        out invalidReason,
        out effectiveRequiredScopes,
        requiredApiPermissions
      );

      if (string.IsNullOrWhiteSpace(invalidReason)) {
        invalidReason = string.Empty;
      }

      if (outcome == AccessTokenValidator.ValidationOutcome.AccessGranted) {
        return true;
      }
      else if (
        outcome == AccessTokenValidator.ValidationOutcome.AccessDeniedTokenRequired
      ) {
        httpReturnCode = 401;
        httpReasonPhrase = "Unauthorized (token required)"; //low detail - just a hint for the client
      }
      else {
        if (invalidReason.Contains("xpired")) { //<< 401 semantical more correct for expired tokens than 403)
          httpReturnCode = 401;
          httpReasonPhrase = "Unauthorized (expired)"; //low detail - just a hint for the client
        }
        else {
          httpReturnCode = 403;
          httpReasonPhrase = "Forbidden (bad token)"; //low detail - just a hint for the client
        }
      }

      if (httpReturnCode == 401) {
        challengeHeaders = BuildChallengeHeaders(httpReturnCode, effectiveRequiredScopes);
      }

      return false;
    }

    #endregion

    /// <summary>
    /// This method will:
    ///   analyze/introspect the token,
    ///   resolve the subject identity,
    ///   resolve the permitted scopes,
    ///   and optinally compare the permitted scope to the requiredScopes (if provided).
    /// If configured, an internal cache for the outcome will be enabled.
    /// NOTE: this method can only be called after 'AccessTokenValidator.ConfigureTokenIntrospection(...)
    /// has been called before, otherwise it will throw an Exception!
    /// </summary>
    /// <param name="rawToken">
    /// The recived token (or null, if no token was provided).
    /// Make sure, that this method is called also if there was no Token, to support anonymous access (if configured)
    /// </param>
    /// <param name="contractType"></param>
    /// <param name="targetContractMethod">the api method, which the client is trying to invoke</param>
    /// <param name="callingMachine">the client machine (name or IP-address), which has initiated the service-request</param>
    /// <param name="invalidReason"> some detail why the token is invalid</param>
    /// <param name="requiredApiPermissions">
    /// OPTIONAL: all expressions, passed to this array,
    /// are required to be present within the permittedScopes that are evaluated when introspecting the token.
    /// If one is not present, the validation outcome will be negative (access should be denied in this case).
    /// NOTE: related to the configured 'apiPermissionPrefix', the evaluated scopes from the token (but NOT the requiredApiPermissions)
    /// are required to compliant with this (otherwise they will be ignored)
    /// </param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    public static ValidationOutcome TryValidateTokenAndEvaluateScopes(
      string rawToken,
      Type contractType,
      MethodInfo targetContractMethod,
      string callingMachine, out string invalidReason,
      params string[] requiredApiPermissions
    ) {
      string[] ignoredEffectiveRequiredScopes;
      return ValidateTokenAndEvaluateScopesCore(
        rawToken, contractType, targetContractMethod, string.Empty, callingMachine,
        out invalidReason, out ignoredEffectiveRequiredScopes, requiredApiPermissions
      );
    }

    /// <summary>
    /// Internal core of 'TryValidateTokenAndEvaluateScopes' with the additional API group name (logical name, "" if
    /// not known), which is used for the resolution chain of the AccessTokenManager.
    /// If no 'IAuthRequirementsProvider' is configured (wire-up via the AccessTokenManager), the manager decides
    /// whether a token is required (fail closed, except anonymous logical names) and which scopes are required.
    /// </summary>
    internal static ValidationOutcome ValidateTokenAndEvaluateScopesCore(
      string rawToken,
      Type contractType,
      MethodInfo targetContractMethod,
      string apiGroupName,
      string callingMachine,
      out string invalidReason,
      out string[] effectiveRequiredScopes,
      string[] requiredApiPermissions
    ) {

      if (apiGroupName == null) {
        apiGroupName = string.Empty;
      }

      if (_IntrospectorSelector == null) {
        throw new Exception(
          $"The {nameof(AccessTokenValidator)} can be used only when {nameof(AccessTokenValidator)}.{nameof(ConfigureTokenValidation)}(...) has been called before!"
        );
      }

      ValidationOutcome outcome;

      bool tokenRequired;
      string authTokenSourceIdentifier;
      string[] requiredApiPermissionsFromProvider;
      if (_RequirementsProvider != null) {
        //legacy: the provider alone decides (as before)
        tokenRequired = _RequirementsProvider.IsAuthtokenRequired(
          contractType, targetContractMethod,
          out authTokenSourceIdentifier, out requiredApiPermissionsFromProvider
        );
      }
      else {
        tokenRequired = EvaluateRequirementsViaAccessTokenManager(
          contractType, apiGroupName, out requiredApiPermissionsFromProvider
        );
        authTokenSourceIdentifier = string.Empty; //'not known' -> resolved by the manager's chain
      }

      string subject = null;
      bool fromCache = false;
      string[] permittedScopes = new string[] { };

      if (string.IsNullOrWhiteSpace(rawToken)) {

        if (tokenRequired == false || _AnonymousSubjectName != null) {

          //anonymous support
          outcome = ValidationOutcome.AccessGranted;

          subject = _AnonymousSubjectName;
          if (_PermittedScopesVisitorMethod != null) {
            var scopes = new List<string>();
            _PermittedScopesVisitorMethod.Invoke(_AnonymousSubjectName, scopes);
            permittedScopes = scopes.ToArray();
          }

          invalidReason = string.Empty;
        }
        else {
          outcome = ValidationOutcome.AccessDeniedTokenRequired;
          invalidReason = "No Token provided";
        }
      }
      else {

        rawToken = StripTokenPrefix(rawToken);

        //analyze token
        GetCachedIntrospectionResult(
          rawToken,
          contractType,
          targetContractMethod,
          callingMachine,
          authTokenSourceIdentifier,
          apiGroupName,
          out bool isActive,
          out invalidReason,
          out permittedScopes,
          out subject,
          out fromCache,
          out bool unkownIssuer
        );

        if (isActive) {
          outcome = ValidationOutcome.AccessGranted;
        }
        else if (unkownIssuer) {
          outcome = ValidationOutcome.AccessDeniedTokenFromBadOrigin;
        }
        else {
          outcome = ValidationOutcome.AccessDeniedTokenInvalid;
        }

      }

      var requiredScopes = new List<string>();
      if (requiredApiPermissions != null) {
        foreach (string p in requiredApiPermissions) {
          requiredScopes.Add(p.StartsWith(_ApiPermissionPrefix) ? p : _ApiPermissionPrefix + p);
        }
      }
      if (requiredApiPermissionsFromProvider != null) {
        foreach (string p in requiredApiPermissionsFromProvider) {
          if (_RequirementsProvider == null) {
            //the scopes from the AccessTokenManager are already final (prefix applied or explicitly suppressed)
            requiredScopes.Add(p);
          }
          else {
            requiredScopes.Add(p.StartsWith(_ApiPermissionPrefix) ? p : _ApiPermissionPrefix + p);
          }
        }
      }
      effectiveRequiredScopes = requiredScopes.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

      //evaluate scope based api permissions
      if (outcome == ValidationOutcome.AccessGranted) {
        foreach (string requiredScope in requiredScopes) {
          if (!permittedScopes.Where((s) => s.Equals(requiredScope, StringComparison.CurrentCultureIgnoreCase)).Any()) {
            outcome = ValidationOutcome.AccessDeniedMissingPrivileges;
            invalidReason = "Required scope not present";
            break;
          }
        }
      }

      //default logging
      if (outcome != ValidationOutcome.AccessGranted) {
        string tokenContentProbe = "[EMPTY]";
        if (!string.IsNullOrWhiteSpace(rawToken)) {
          if (rawToken.Length < 16) {
            //short tokens are fully masked
            tokenContentProbe = new string('*', rawToken.Length);
          }
          else {
            //longer tokens: only show the last 3 chars
            tokenContentProbe = "...**********" + rawToken.Substring(rawToken.Length - 3);
          }
        }
        SecLogger.LogWarning(
          2078854485086216369L, 73001,
          "Negative outcome when validating Auth-Token '{tokenContentProbe}': {tokenInactiveReason}",
          tokenContentProbe, invalidReason
        );
      }

      //push the validated token into the register of the token source which has accepted it
      if (outcome == ValidationOutcome.AccessGranted && !string.IsNullOrWhiteSpace(rawToken)) {
        string matchedTokenSourceId = AccessTokenManager.PeekMatchedTokenSourceId();
        if (!string.IsNullOrEmpty(matchedTokenSourceId)) {
          AccessTokenManager.PushValidatedToken(matchedTokenSourceId, rawToken, subject, permittedScopes);
        }
      }

      if (_RawTokenExposalMethod != null && outcome == ValidationOutcome.AccessGranted) {
        _RawTokenExposalMethod.Invoke(rawToken, targetContractMethod, subject, permittedScopes);
      }

      //do auditing, if configured...
      if (_AuditingHook != null) {
        _AuditingHook.Invoke(
          targetContractMethod,
          callingMachine,
          outcome,
          subject,
          permittedScopes,
          requiredScopes.ToArray(),
          fromCache,
          invalidReason
        );
      }

      return outcome;
    }

    /// <summary>
    /// Evaluates (without an 'IAuthRequirementsProvider') via the AccessTokenManager, whether a token is required
    /// and which scopes are required: a token is ALWAYS required (fail closed), except the contract is explicitly
    /// anonymous ('AuthTokenSourceAttribute(null)') or any logical name of the call was registered via 'MapAnonymous'.
    /// The required scopes accumulate (AND): 'RequireScope' for all calls and for every logical name of the call,
    /// plus the legacy 'RequiredApiPermissionAttribute' of the contract.
    /// </summary>
    private static bool EvaluateRequirementsViaAccessTokenManager(
      Type contractType, string apiGroupName, out string[] requiredScopes
    ) {
      string[] logicalNames;
      if (!AccessTokenManager.TryGetLogicalNamesForContract(contractType, apiGroupName, out logicalNames)) {
        requiredScopes = new string[] { };
        return false;
      }
      if (AccessTokenManager.IsAnonymous(logicalNames)) {
        requiredScopes = new string[] { };
        return false;
      }
      List<string> scopes = new List<string>(AccessTokenManager.GetRequiredScopes(logicalNames));
      string[] attributeScopes;
      if (contractType != null && RequiredApiPermissionAttribute.TryPickFrom(contractType, out attributeScopes) && attributeScopes != null) {
        foreach (string attributeScope in attributeScopes) {
          scopes.Add(attributeScope.StartsWith(_ApiPermissionPrefix) ? attributeScope : _ApiPermissionPrefix + attributeScope);
        }
      }
      requiredScopes = scopes.ToArray();
      return true;
    }

    private static void GetCachedIntrospectionResult(
      string rawToken,
      Type targetContract,
      MethodInfo targetContractMethod,
      string callingMachine,
      string authTokenSourceIdentifier, //can be NULL
      string apiGroupName,
      out bool isActive,
      out string inactiveReason,
      out string[] permittedScopes,
      out string subject,
      out bool fromCache,
      out bool unknownIssuer
    ) {
      unknownIssuer = false;
      AccessTokenManager.SetMatchedTokenSourceId(null);
      string resolutionKey = BuildCacheResolutionKey(targetContract, apiGroupName);

      lock (_Cache) {

        CacheEntry result = null;
        int idx = 0;
        foreach (CacheEntry entry in _Cache) {
          if (entry.RawToken == rawToken && entry.CallerHost == callingMachine && entry.ResolutionKey == resolutionKey && DateTime.Now < entry.CachableUntil) {
            result = entry;
            break;
          }
          idx++;
        }

        if (result != null) {

          if (idx > 20) {
            //roll back to first position!
            _Cache.RemoveAt(idx);
            _Cache.Insert(0, result);
          }

          isActive = result.IsActive;
          inactiveReason = result.InactiveReason;
          permittedScopes = result.PermittedScopes;
          subject = result.Subject;
          fromCache = true;
          AccessTokenManager.SetMatchedTokenSourceId(result.MatchedTokenSourceId);

          return;
        }

      }

      fromCache = false;
      subject = string.Empty;
      permittedScopes = new string[] { };
      IAccessTokenIntrospector introspector = null;
      Dictionary<string, object> extractedClaims = null;

      //the API group is handed over to the manager's lookup (the lookup delegate has no parameter for it)
      AccessTokenManager.SetCurrentApiGroupName(apiGroupName);
      try {
        introspector = _IntrospectorSelector.Invoke(
          authTokenSourceIdentifier, targetContract, targetContractMethod, callingMachine,
          () => {
            // an explicitely requested pre-visit of tokens, which are assumed to be a JWT...
            if (string.IsNullOrWhiteSpace(rawToken)) {
              return null;
            }
            try {
              JwtContent jwtContent = JWT.Payload<JwtContent>(rawToken);
              //...with the goal to read the issuer BEFORE introspecting/validating the token
              return jwtContent.iss;
              //this needs to be done sometimes, to select issuer dedicated-introspectors 
            }
            catch {
              return null;
            }
          }
        );
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex.Wrap(73004, "Introspector selection hook has thrown an Exception!"));
        unknownIssuer = true; //explicit documented semantic, when null was returned by the IntrospectorSelector
        isActive = false;
        inactiveReason = "Introspection not possible (SL-EXP)";
        return;
      }
      finally {
        AccessTokenManager.SetCurrentApiGroupName(null);
      }

      if (introspector == null) {
        unknownIssuer = true; //explicit documented semantic, when null was returned by the IntrospectorSelector
        isActive = false;
        inactiveReason = "Introspection not possible (no Introspector available)"; //(introspector == null)
        return;
      }

      try {
        introspector.IntrospectAccessToken(
          rawToken,
          out isActive,
          out extractedClaims
        );
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex.Wrap(73005, "Introspector has thrown an Exception!"));
        isActive = false;
        inactiveReason = "Introspection failed (IS-EXP)";
        return;
      }

      //subject will always be extracted (if possible)
      if (extractedClaims != null && extractedClaims.ContainsKey("sub")) {
        object subClaim = extractedClaims["sub"];
        if (subClaim != null) {
          subject = subClaim.ToString();
        }
      }

      if (isActive) {

        var scopes = new List<string>();
        if (extractedClaims != null && extractedClaims.ContainsKey("scope")) {
          object scopeClaim = extractedClaims["scope"];
          if (scopeClaim != null) {
            scopes = scopeClaim.ToString().Split(' ').Where((s) => !string.IsNullOrWhiteSpace(s)).ToList();
          }
        }
        if (_PermittedScopesVisitorMethod != null) {
          try {
            _PermittedScopesVisitorMethod.Invoke(subject, scopes);
          }
          catch (Exception ex) {
            DevLogger.LogCritical(ex.Wrap(73006, "ScopeVisitor has thrown an Exception!"));
            isActive = false;
            inactiveReason = "Introspection failed (SV-EXP)";
            return;
          }
        }
        permittedScopes = scopes.ToArray();
        inactiveReason = null;

      }
      else {

        inactiveReason = "No details provided";

        if (extractedClaims != null) {
          try {
            if (extractedClaims.ContainsKey("inactive_reason") && extractedClaims["inactive_reason"] != null) {
              //explicitely delivered detail (but not standard)
              inactiveReason = extractedClaims["inactive_reason"].ToString();
            }
            else if (extractedClaims.ContainsKey("error_description") && extractedClaims["error_description"] != null) {
              //part of the standard, but different semantic (means, the the introspection itself failed)
              inactiveReason = extractedClaims["error_description"].ToString();
            }
            else if (extractedClaims.ContainsKey("error") && extractedClaims["error"] != null) {
              //part of the standard, but different semantic (means, the the introspection itself failed)
              inactiveReason = extractedClaims["error"].ToString();
            }
            else if (extractedClaims.ContainsKey("exp")){
              //last fallback, if no details are present: check for expiration by our own
              object expClaim = extractedClaims["exp"];
              if (expClaim != null) {
                long exp = Convert.ToInt64(expClaim);
                DateTime expirationTimeUtc = new DateTime(1970, 01, 01, 0, 0, 0, DateTimeKind.Utc).AddSeconds(exp);
                if (DateTime.UtcNow > expirationTimeUtc) {
                  inactiveReason = $"Expired (at {expirationTimeUtc.ToLocalTime().ToString("u")})";
                }
              }
            }
          }
          catch {
          }
        }

      }

      if (_IntrospectionResultCachingMinutes > 0) {
        lock (_Cache) {

          //protect against DOS attack
          if (_Cache.Count >= 10000) {
            _Cache.RemoveAt(9999);
          }

          CacheEntry newEntry = new CacheEntry();

          newEntry.RawToken = rawToken;
          newEntry.CallerHost = callingMachine;
          newEntry.ResolutionKey = resolutionKey;
          newEntry.IsActive = isActive;
          newEntry.InactiveReason = inactiveReason;
          newEntry.PermittedScopes = permittedScopes;
          newEntry.Subject = subject;
          newEntry.MatchedTokenSourceId = AccessTokenManager.PeekMatchedTokenSourceId();
          newEntry.CachableUntil = DateTime.Now.AddMinutes(_IntrospectionResultCachingMinutes);

          _Cache.Insert(0, newEntry);

          //remove expired entries
          for (int i = _Cache.Count - 1; i > 0; i--) {
            if (_Cache[i].CachableUntil < DateTime.Now) {
              _Cache.RemoveAt(i);
            }
          }

        }
      }

      return;
    }

    /// <summary>
    /// Builds the cache discriminator for an introspection result. Legacy callers (without API group and with a
    /// configured IAuthRequirementsProvider) get "", which keeps the former cache behavior unchanged. In manager mode
    /// (no IAuthRequirementsProvider) the API group and the contract are part of the key, because they drive the
    /// resolution of the token source(s).
    /// </summary>
    private static string BuildCacheResolutionKey(Type targetContract, string apiGroupName) {
      string groupPart = string.Empty;
      if (apiGroupName != null) {
        groupPart = apiGroupName;
      }
      if (_RequirementsProvider != null) {
        return groupPart; //legacy: unchanged cache behavior
      }
      string[] additionalNames = AccessTokenManager.GetCurrentAdditionalLogicalNames();
      if (additionalNames != null && additionalNames.Length > 0) {
        //additional logical names (scheme names) drive the resolution as well
        groupPart = groupPart + "|" + string.Join(",", additionalNames);
      }
      string contractPart = string.Empty;
      if (targetContract != null) {
        contractPart = targetContract.FullName;
      }
      return groupPart + "|" + contractPart;
    }

    private readonly static string[] _KnownTokenPrefixes = new string[] { "Bearer", "JWT" };
    internal static string StripTokenPrefix(string rawToken) {     
      foreach (string prefix in _KnownTokenPrefixes) {
        if (rawToken != null && rawToken.StartsWith(prefix + " ", StringComparison.CurrentCultureIgnoreCase)) {
          return rawToken.Substring(prefix.Length + 1);
        }
      }
      return rawToken;
    } 

  }

}
