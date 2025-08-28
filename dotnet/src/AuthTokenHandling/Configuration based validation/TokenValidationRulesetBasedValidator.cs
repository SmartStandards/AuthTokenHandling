using Jose;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Security.AccessTokenHandling {

  public class TokenValidationRulesetBasedValidator {

    #region " Constructors & Ruleset "

    public TokenValidationRulesetBasedValidator() {
      _Ruleset = new TokenValidationRuleset();
    }

    public TokenValidationRulesetBasedValidator(TokenValidationRuleset ruleset) {
      _Ruleset = ruleset;
    }

    public TokenValidationRulesetBasedValidator(string rulesetFileName, int fileReloadAfterMinutes = 10) {
      if (String.IsNullOrWhiteSpace(rulesetFileName)) {
        throw new Exception("rulesetFileName mut not be empty!");
      }
      _FileFullName = rulesetFileName;
      _FileReloadAfterMinutes = fileReloadAfterMinutes;
    }

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private TokenValidationRuleset _Ruleset;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private string _FileFullName = null;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private int _FileReloadAfterMinutes = 15;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private DateTime _FileValidUntil = DateTime.MaxValue;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private Dictionary<string, IAccessTokenIntrospector> _IntrospectorsPerIssuer = new Dictionary<string, IAccessTokenIntrospector>();

    public TokenValidationRuleset Ruleset {
      get {
        if (!string.IsNullOrWhiteSpace(_FileFullName) && _FileValidUntil < DateTime.Now) {
          lock (_IntrospectorsPerIssuer) {
            string rawFileContent = File.ReadAllText(_FileFullName, Encoding.Default);
            _Ruleset = JsonConvert.DeserializeObject<TokenValidationRuleset>(rawFileContent);
            _FileValidUntil = DateTime.Now.AddMinutes(_FileReloadAfterMinutes);
            _IntrospectorsPerIssuer.Clear();
          }
        }
        return _Ruleset;
      }
    }

    #endregion

    /// <summary>
    /// (NOTE: can be wired-up with the AccessTokenValidator as IntrospectorSelectorMethod)
    /// </summary>
    /// <param name="calledMethod"></param>
    /// <param name="callingMachine"></param>
    /// <param name="tryReadJwtIssuerMethod"></param>
    /// <returns></returns>
    public IAccessTokenIntrospector SelectIntrospectorByJwtIssuer(
      string calledMethod, string callingMachine, Func<string> tryReadJwtIssuerMethod
    ) {
      string issuer = tryReadJwtIssuerMethod.Invoke();
      return this.GetIntrospectorByIssuer(issuer);
    }

    private IAccessTokenIntrospector GetIntrospectorByIssuer(string issuer) {

      if (string.IsNullOrWhiteSpace(issuer)) {
        return null;//deny this issuer
      }

      var issProfile = this.GetIssuerProfile(issuer);
      if (issProfile == null || issProfile.Disabled) {
        return null;//deny this issuer
      }

      lock (_IntrospectorsPerIssuer) {
        if (_IntrospectorsPerIssuer.ContainsKey(issuer)) {
          return _IntrospectorsPerIssuer[issuer];
        }
        /////////////////////////////////////////////////////////
        IAccessTokenIntrospector newIntrospector;

        if (string.IsNullOrWhiteSpace(issProfile.IntrospectorUrl)) {

          newIntrospector = new OAuthTokenIntrospectionEndpointCaller(
            () => issProfile.IntrospectorUrl,
            () => issProfile.IntrospectorAuthHeader
          );

        }
        else {

          newIntrospector = new LocalJwtIntrospector(
            (jwt) => ValidateJwtSignature(jwt, issProfile)
          );

        }

        /////////////////////////////////////////////////////////
        _IntrospectorsPerIssuer[issuer] = newIntrospector;
        return newIntrospector;
      }
    }

    private IssuerProfileConfigurationEntry GetIssuerProfile(string issuerName) {
      IssuerProfileConfigurationEntry result = null;
      result = this.Ruleset.IssuerProfiles.Where(
        e => e.IssuerName.Equals(issuerName, StringComparison.InvariantCultureIgnoreCase)
      ).SingleOrDefault();
      if (result == null) {
        result = this.Ruleset.IssuerProfiles.Where(
          e => e.IssuerName.Equals("(unknown)", StringComparison.InvariantCultureIgnoreCase)
        ).SingleOrDefault();
      }
      if (result != null && result.Disabled) {
        result = null;
      }
      return result;
    }

    private static bool ValidateJwtSignature(string rawJwt, IssuerProfileConfigurationEntry issuerProfile) {
      JwtContent jwtContent = null;
      try {

        if (string.IsNullOrWhiteSpace(rawJwt)) {
          return false;
        }

        jwtContent = JWT.Payload<JwtContent>(rawJwt);
         
        if (issuerProfile == null) {
          return false;
        }

        IDictionary<string, object> headers = JWT.Headers(rawJwt);
        string alg = headers["alg"].ToString();
        bool useComplexJwk = (alg.StartsWith("RS", StringComparison.CurrentCultureIgnoreCase));

          if (useComplexJwk) {
            if (string.IsNullOrWhiteSpace(issuerProfile.JwkE)) {
              //'Authorization'-Header contains an invalid bearer token (expecting JWK for alg '{alg}')!
              return false;
            }
            else {
              // can be convertd from base64 PEM via this tool:  https://8gwifi.org/jwkconvertfunctions.jsp
              Jwk jwk = new Jwk(
                e: issuerProfile.JwkE,
                n: issuerProfile.JwkN,
                p: issuerProfile.JwkP,
                q: issuerProfile.JwkQ,
                d: issuerProfile.JwkD,
                dp: issuerProfile.JwkDp,
                dq: issuerProfile.JwkDq,
                qi: issuerProfile.JwkQi
              );
              jwtContent = JWT.Decode<JwtContent>(rawJwt, jwk);
            }
          }
          else {
            if (string.IsNullOrWhiteSpace(issuerProfile.JwtSignKey)) {
              //expecting 'JwtSignKey' for alg '{alg}'!
              return false;
            }
            else {
              byte[] jwtSignKeyBytes = Encoding.ASCII.GetBytes(issuerProfile.JwtSignKey);
              jwtContent = JWT.Decode<JwtContent>(rawJwt, jwtSignKeyBytes);
            }
          }

          return true;
        }
        catch (Exception ex) {
          //'decode failure
          return false;
        }
    }

    /// <summary>
    /// (NOTE: can be wired-up with the AccessTokenValidator as.ScopeEnumerationHookMethod)
    /// </summary>
    /// <param name="subject"></param>
    /// <param name="permittedScopes"></param>
    public void ExtendPermittedScopesViaConfig(string subject, List<string> permittedScopes) {

      SubjectProfileConfigurationEntry subjectProfile = null;

      if (!String.IsNullOrWhiteSpace(subject)) {

        subjectProfile = this.Ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals(subject, StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        if (subjectProfile == null) {
          //fallback
          subjectProfile = this.Ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals("(generic)", StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        }

      }

      if (subjectProfile == null || subjectProfile.Disabled) {
        permittedScopes.Clear();
        return;
      }

      if (!this.Ruleset.ApplyApiPermissionsFromJwtScope) {
        if (!this.Ruleset.ApplyDataAccessClearancesFromJwtScope) {
          permittedScopes.Clear();
        }
        else {
          foreach (var scope in permittedScopes.Where((s)=> s.StartsWith("API:")).ToArray()) {
            permittedScopes.Remove(scope);
          }
        }
      }
      else if (!this.Ruleset.ApplyDataAccessClearancesFromJwtScope) {
        foreach (var scope in permittedScopes.Where((s) => !s.StartsWith("API:")).ToArray()) {
          permittedScopes.Remove(scope);
        }
      }

      //import permissions/clearances from profile
      if (subjectProfile.DefaultApiPermissions != null) {
        foreach (var defaultApiPermission in subjectProfile.DefaultApiPermissions) {
          if (!permittedScopes.Contains("API:" + defaultApiPermission))
            permittedScopes.Add("API:" + defaultApiPermission);
        }
      }
      if (subjectProfile.DefaultDataAccessClearances != null) {
        foreach (string dimensionName in subjectProfile.DefaultDataAccessClearances.Keys) {
          string[] values = subjectProfile.DefaultDataAccessClearances[dimensionName].Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
          foreach (var value in values) {
            if (!permittedScopes.Contains(dimensionName + ":" + value))
              permittedScopes.Add(dimensionName + ":" + value);
          }
        }
      }

    }

  }

  /*
   Sample for integration:       
    AccessTokenValidator.ConfigureTokenIntrospection(
      introspector,
      scopeEnumerationHook: (string subject, List<string> permittedScopes) => {
        //1. verify and/or extend scopes based on our config file
        _TokenValidationRulesetBasedValidator.ExtendPermittedScopesViaConfig(subject,permittedScopes);
        //2. also apply the data-scopes to the MAC
        AccessControlContext.ApplyClearances(subject,permittedScopes.Where((s)=> s.Contains(":") && !s.StartsWith("API:")));
      },
      anonymousSubjectName: "(anonymous)",
      introspectionResultCachingMinutes: 0,
      auditingHook: auditingHook
    );
   */

}
