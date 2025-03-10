﻿using Jose;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Security.AccessTokenHandling {

  public partial class AccessTokenValidator {

    private AccessTokenValidator() {
    }

    private static List<CacheEntry> _Cache = new List<CacheEntry>();

    private class CacheEntry {
      public string RawToken { get; set; }
      public string CallerHost { get; set; }
      public bool IsActive { get; set; }
      public string[] PermittedScopes { get; set; }
      public string Subject { get; set; }
      public string ValidationOutcomeMessage { get; set; }
      public DateTime CachableUntil { get; set; }
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
    /// <param name="httpReturnCode"></param>
    /// <param name="failedReason"></param>
    /// <returns></returns>
    public static bool TryValidateHttpAuthHeader (
      string rawAuthHeader, Type contractType, MethodInfo calledContractMethod, string callingMachine, ref int httpReturnCode, ref string failedReason
    ) {
      var noExplicitelyRequiredApiPermissions = new string[] { };
      return TryValidateHttpAuthHeader(
        rawAuthHeader, contractType, calledContractMethod, callingMachine, ref httpReturnCode, ref failedReason, noExplicitelyRequiredApiPermissions
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
    /// <param name="httpReturnCode"></param>
    /// <param name="requiredApiPermissions"></param>
    /// <param name="failedReason"></param>
    /// <returns></returns>
    public static bool TryValidateHttpAuthHeader(
      string rawAuthHeader, Type contractType, MethodInfo calledContractMethod, string callingMachine,
      ref int httpReturnCode, ref string failedReason, params string[] requiredApiPermissions
    ) {

      string rawToken = rawAuthHeader;
      if (rawToken != null && rawToken.StartsWith("Bearer ", StringComparison.CurrentCultureIgnoreCase)) {
        rawToken = rawToken.Substring(7);
      }

      ValidationOutcome outcome = TryValidateTokenAndEvaluateScopes(
        rawToken, contractType, calledContractMethod, callingMachine, requiredApiPermissions
      );

      if (outcome == AccessTokenValidator.ValidationOutcome.AccessGranted) {
        return true;
      }
      else if (outcome == AccessTokenValidator.ValidationOutcome.AccessDeniedTokenRequired) {
        httpReturnCode = 401;
      }
      else {
        httpReturnCode = 403;
      }
      failedReason = Enum.GetName(typeof(AccessTokenValidator.ValidationOutcome), outcome);
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
    /// <param name="callingMachine">the client machine (name or IP-address), which has initiated the service-request</param>
    /// <param name="targetContractMethod">the api method, which the client is trying to invoke</param>
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
      string callingMachine,
      params string[] requiredApiPermissions
    ) {

      if (_IntrospectorSelector == null) {
        throw new Exception(
          $"The {nameof(AccessTokenValidator)} can be used only when {nameof(AccessTokenValidator)}.{nameof(ConfigureTokenValidation)}(...) has been called before!"       
        );
      }
    
      ValidationOutcome outcome;

      bool tokenRequired = _RequirementsProvider.IsAuthtokenRequired(
        contractType, targetContractMethod, 
        out string authTokenSourceIdentifier, out string[] requiredApiPermissionsFromProvider
      );

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

        }
        else {
          outcome = ValidationOutcome.AccessDeniedTokenRequired;
        }
      }
      else {

        if (rawToken.StartsWith("Bearer ", StringComparison.CurrentCultureIgnoreCase)) {
          rawToken = rawToken.Substring(7);
        }

        //analyze token
        GetCachedIntrospectionResult(
          rawToken,
          contractType,
          targetContractMethod,
          callingMachine,
          authTokenSourceIdentifier,
          out bool isActive,
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
          requiredScopes.Add(p.StartsWith(_ApiPermissionPrefix) ? p : _ApiPermissionPrefix + p);
        }
      }

      //evaluate scope based api permissions
      if (outcome == ValidationOutcome.AccessGranted) { 
        foreach (string requiredScope in requiredScopes) {
          if (!permittedScopes.Where((s) => s.Equals(requiredScope, StringComparison.CurrentCultureIgnoreCase)).Any()) {
            outcome = ValidationOutcome.AccessDeniedMissingPrivileges;
            break;
          }
        }    
      }

      if(_RawTokenExposalMethod != null && outcome == ValidationOutcome.AccessGranted) {
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
          fromCache
        );
      }

      return outcome;
    }

    private static void GetCachedIntrospectionResult(
      string rawToken,
      Type targetContract,
      MethodInfo targetContractMethod,
      string callingMachine,
      string authTokenSourceIdentifier, //can be NULL
      out bool isActive,
      out string[] permittedScopes,
      out string subject,
      out bool fromCache,
      out bool unknownIssuer
    ) {
      unknownIssuer = false;

      lock (_Cache) {
        CacheEntry result = null;
        int idx = 0;
        foreach (CacheEntry entry in _Cache) {
          if (entry.RawToken == rawToken && entry.CallerHost == callingMachine && DateTime.Now < entry.CachableUntil) {
            result = entry;
            break;
          }
          idx++;
        }

        if (result != null) {

          if (idx > 20) {
            _Cache.RemoveAt(idx);
            _Cache.Insert(0, result);
          }

          isActive = result.IsActive;
          permittedScopes = result.PermittedScopes;
          subject = result.Subject;
          fromCache = true;
          
          return;
        }
        fromCache = false;

        IAccessTokenIntrospector introspector = _IntrospectorSelector.Invoke(
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

        subject = string.Empty;
        permittedScopes = new string[] { };

        if (introspector != null) {

          introspector.IntrospectAccessToken(
            rawToken,
            out isActive,
            out Dictionary<string, object> extractedClaims
          );

          if (extractedClaims != null && extractedClaims.ContainsKey("sub")) {
            object subClaim = extractedClaims["sub"];
            if (subClaim != null) {
              subject = subClaim.ToString();
            }
          }

          if (isActive) {
            var scopes = new List<string>();
            if (extractedClaims.ContainsKey("scope")) {
              object scopeClaim = extractedClaims["scope"];
              if (scopeClaim != null) {
                scopes = scopeClaim.ToString().Split(' ').Where((s) => !string.IsNullOrWhiteSpace(s)).ToList();
              }
            }
            if (_PermittedScopesVisitorMethod != null) {
              _PermittedScopesVisitorMethod.Invoke(subject, scopes);
            }
            permittedScopes = scopes.ToArray();
          }

        }
        else { //introspector == null:   
          unknownIssuer = true; //explicit documented semantic, when null was returned by the IntrospectorSelector
          isActive = false;
          return;
        }

      }

      if (_IntrospectionResultCachingMinutes > 0) {

        //protect against DOS attack
        if (_Cache.Count >= 10000) {
          _Cache.RemoveAt(9999);
        }

        var newEntry = new CacheEntry();

        newEntry.RawToken = rawToken;
        newEntry.CallerHost = callingMachine;
        newEntry.IsActive = isActive;
        newEntry.PermittedScopes = permittedScopes;
        newEntry.Subject = subject;
        newEntry.CachableUntil = DateTime.Now.AddMinutes(_IntrospectionResultCachingMinutes);

        _Cache.Insert(0, newEntry);

        //remove expired entries
        for (int i = _Cache.Count - 1; i > 0; i--) {
          if (_Cache[i].CachableUntil < DateTime.Now) {
            _Cache.RemoveAt(i);
          }
        }

      }

      return;
    }

  }

}
