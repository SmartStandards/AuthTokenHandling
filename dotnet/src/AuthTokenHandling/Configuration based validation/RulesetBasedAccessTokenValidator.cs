using Jose;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Security.AccessTokenHandling {

  public class AccessTokenValidationRulesetAdapterl {

    /// <summary>
    /// (NOTE: can be wired-up with the AccessTokenValidator as.ScopeEnumerationHookMethod)
    /// </summary>
    /// <param name="subject"></param>
    /// <param name="permittedScopes"></param>
    public void EnumerateScopes(string subject, List<string> permittedScopes) {





    }

    /// <summary>
    /// (NOTE: can be wired-up with the AccessTokenValidator as IntrospectorSelectorMethod)
    /// </summary>
    /// <param name="tryReadJwtIssuerMethod"></param>
    /// <returns></returns>
    public IAccessTokenIntrospector SelectIntrospectorByJwtIssuer(Func<string> tryReadJwtIssuerMethod) {




    }

  }

  public class RulesetBasedAccessTokenValidator {

    #region " Constructors & Ruleset "

    public RulesetBasedAccessTokenValidator() {
      _Ruleset = new TokenValidationRuleset();
    }

    public RulesetBasedAccessTokenValidator(TokenValidationRuleset ruleset) {
      _Ruleset = ruleset;
    }

    /// <summary>
    /// </summary>
    /// <param name="fileFullName">the name of a JSON-File, which contains a serialized 'TokenValidationRuleset'</param>
    /// <param name="reloadIntervalMinutes"></param>
    public RulesetBasedAccessTokenValidator(string fileFullName, int reloadIntervalMinutes = 15, IAccessTokenIntrospector introspector = null) {
      _FileFullName = fileFullName;
      _ReloadIntervalMinutes = reloadIntervalMinutes;
      _FileValidUntil = DateTime.MinValue;
      if (introspector != null) {
        _Introspector = introspector;
      }
      else {
        _Introspector = new LocalJwtIntrospector(this.ValidateJwtSignature);
      }
    }

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private TokenValidationRuleset _Ruleset;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private string _FileFullName = null;
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private int _ReloadIntervalMinutes = 1;
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private DateTime _FileValidUntil = DateTime.MaxValue;
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private IAccessTokenIntrospector _Introspector;

    public TokenValidationRuleset Ruleset {
      get {
        if(_FileFullName != null && _FileValidUntil < DateTime.Now) {
          string rawFileContent = File.ReadAllText(_FileFullName, Encoding.Default);
          _Ruleset = JsonConvert.DeserializeObject<TokenValidationRuleset>(rawFileContent);
          _FileValidUntil = DateTime.Now.AddMinutes(_ReloadIntervalMinutes);
        }
        return _Ruleset;
      }
    }

    #endregion

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

    private bool ValidateJwtSignature(string rawJwt) {
      JwtContent jwtContent = null;
      IssuerProfileConfigurationEntry issuerProfile = null;
      try {

        jwtContent = JWT.Payload<JwtContent>(rawJwt);

        issuerProfile = this.GetIssuerProfile(jwtContent.iss);
         
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
              //'Authorization'-Header contains an invalid bearer token (expecting 'JwtSignKey' for alg '{alg}')!
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
          //'Authorization'-Header contains an invalid bearer token (decode failure)
          return false;
        }
    }

    public void ValidateAccessToken(
      string rawToken,
      string callerHost,
      out int authStateCode,
      out string[] permittedScopes,
      out int cachableForMinutes,
      out string identityLabel,
      out string validationOutcomeMessage
    ) {

      TokenValidationRuleset ruleset = this.Ruleset;
      if (_FileFullName != null) {
        cachableForMinutes = Convert.ToInt32(_FileValidUntil.Subtract(DateTime.Now).TotalMinutes);
        if(cachableForMinutes < 0) {
          cachableForMinutes = 0;
        }
      }
      else {
        cachableForMinutes = _ReloadIntervalMinutes;
      }
     
      authStateCode = 1;
      identityLabel = "UNAUTHORIZED";
      validationOutcomeMessage = "";

      if (string.IsNullOrWhiteSpace(rawToken)) {
        identityLabel = "(not authenticated)";
        authStateCode = 0;
        validationOutcomeMessage = "no Token provided";
      }

      bool isActive = false;
      Dictionary<string, object> claims = null;
      try {
         _Introspector.IntrospectAccessToken(rawToken, out isActive, out claims);
      }
      catch (Exception ex) {
        validationOutcomeMessage = "'Authorization'-Header contains an token that could not be verified (introspection failed): " + ex.Message;
        cachableForMinutes = 1140; //invalid forever -> cache 24h
        authStateCode = -2;
      }

      SubjectProfileConfigurationEntry subjectProfile = null;

      //if we have not failed until here -> validate the SUBJECT (try to find corr. profile)
      if (authStateCode == 1 && claims != null && !String.IsNullOrWhiteSpace(claims["sub"] as string)) {
        string subjectName = claims["sub"] as string;
        subjectProfile = this.Ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals(subjectName, StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        if (subjectProfile == null) {
          //fallback
          subjectProfile = ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals("(generic)", StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        }
        if (subjectProfile == null) {
          validationOutcomeMessage = "'Authorization'-Header contains an invalid bearer token (unknown subject)!";
          authStateCode = -2;
        }
        else if (subjectProfile.Disabled) {
          validationOutcomeMessage = "subject is blocked!";
          authStateCode = -2;
          subjectProfile = null;
        }
      }

      if (subjectProfile == null) {
        //this will be loaded for not-authenticated requests (if existing)
        subjectProfile = ruleset.SubjectProfiles.Where(e => e.SubjectName.Equals("(anonymous)", StringComparison.InvariantCultureIgnoreCase)).SingleOrDefault();
        if (subjectProfile != null && subjectProfile.Disabled) {
          subjectProfile = null;
        }
      }

      //evaluate the optional Firewall-Rules (can only be done after a profile was assigned...)
      if (subjectProfile != null && subjectProfile.AllowedHosts != null && !subjectProfile.AllowedHosts.Contains("*")) {
        //TODO: *-resolving via regex!!!!!!!!!! + fallback for DNS-names to IP!!!
        if (!subjectProfile.AllowedHosts.Contains(callerHost.ToLower())) {
          authStateCode = -3;
          validationOutcomeMessage = "access denied by firewall rules";
        }
      }

      if (authStateCode < 0) {
        permittedScopes = new string[] { };
        return;
      }

      var scopes = new List<string>();
      if (subjectProfile == null) {
        identityLabel = "(not authenticated)";
      }
      else {
        identityLabel = subjectProfile.SubjectTitle;
        //import permissions/clearances from profile
        if (subjectProfile.DefaultApiPermissions != null) {
          foreach (var defaultApiPermission in subjectProfile.DefaultApiPermissions) {
            scopes.Add("API:" + defaultApiPermission);
          }
        }
        if (subjectProfile.DefaultDataAccessClearances != null) {
          foreach (string dimensionName in subjectProfile.DefaultDataAccessClearances.Keys) {
            string[] values = subjectProfile.DefaultDataAccessClearances[dimensionName].Split(',').Select(t => t.Trim()).Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
            foreach (var value in values) {
              scopes.Add(dimensionName + ":" + value);
            }
          }
        }
      }

      //if there is a VALID token and we are configured to import permissions/clearances from the JWT-scope field!
      if (authStateCode == 1 && claims != null && ruleset.ApplyApiPermissionsFromJwtScope) {
        string[] jwtScopes;
        string rawScopes = string.Empty;
        if (!String.IsNullOrWhiteSpace(claims["scope"] as string)) {
          rawScopes = claims["scope"] as string;
        }
        jwtScopes = rawScopes.Split(',', ';', ' ').Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
        foreach (string jwtScope in jwtScopes) {
          scopes.Add(jwtScope);
        }
      }

      permittedScopes = scopes.ToArray();
      return;
    }


  }

  public class IntrospectorBasedTokenValidatorsss {

    private IAccessTokenIntrospector _AccessTokenIntrospector;
    private int _PosititveOutcomeCachetimeMinutes;

    public IntrospectorBasedTokenValidator(IAccessTokenIntrospector accessTokenIntrospector, int posititveOutcomeCachetimeMinutes = 2) {
      _AccessTokenIntrospector = accessTokenIntrospector;
      _PosititveOutcomeCachetimeMinutes = posititveOutcomeCachetimeMinutes;
    }

    public void ValidateAccessToken(
      string rawToken, string callerHost, out int authStateCode, out string[] permittedScopes,
      out int cachableForMinutes, out string identityLabel, out string validationOutcomeMessage
    ) {

      Dictionary<string, object> claims = null;
      bool active = false;
      if (!String.IsNullOrWhiteSpace(rawToken)) {
        _AccessTokenIntrospector.IntrospectAccessToken(rawToken, out active, out claims);
      }

      if (active) {
        authStateCode = 1;
        cachableForMinutes = _PosititveOutcomeCachetimeMinutes;
        object buffer = null;
        claims.TryGetValue("username", out buffer);
        if (string.IsNullOrWhiteSpace(buffer as string)) {
          claims.TryGetValue("sub", out buffer);
        }
        if (string.IsNullOrWhiteSpace(buffer as string)) {
          identityLabel = "(authorized)";
        }
        else {
          identityLabel = buffer as string;
        }

        claims.TryGetValue("scope", out buffer);
        if (string.IsNullOrWhiteSpace(buffer as string)) {
          permittedScopes = new string[] { };
        }
        else {
          permittedScopes = (buffer as string).Split(',', ';', ' ').Where(t => !string.IsNullOrWhiteSpace(t)).ToArray();
        }
        validationOutcomeMessage = "";
      }
      else{
        authStateCode = -2;
        permittedScopes = new string[] {};
        cachableForMinutes = 0;
        identityLabel = "UNAUTHORIZED";
        validationOutcomeMessage = "token introspection indicated that token is not active";
      }

    }

  }

}
