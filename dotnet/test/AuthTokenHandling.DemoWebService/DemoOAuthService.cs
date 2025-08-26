using Microsoft.AspNetCore.SignalR.Protocol;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuthServer;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceModel.Channels;
using System.SmartStandards;
using System.Text;
using static System.Net.WebRequestMethods;

public class DemoOAuthService : IOAuthService {

  #region " DEMO-CONFIG "

  // In a real world scenario these would be stored in a secure database!

  private static readonly string _MyOAuthClientId = "11aa22bb33cc";
  private static readonly string _MyOAuthClientSecret = "wow!";

  private static readonly byte[] _MyTotallySecretDemoJwtKey = Encoding.ASCII.GetBytes("TheBigAndMightyFoo");

  private bool ValidateUser(string login) {
    return (login.StartsWith("U_"));
  }
  private bool ValidatePassword(string login, string password) {
    return (!string.IsNullOrWhiteSpace(password) && password == login + "!");
  }

  #endregion

  // This Demo uses JWTs only
  private IAccessTokenIssuer _JwtIssuer = new LocalJwtIssuer(_MyTotallySecretDemoJwtKey, 5, true);
  private IAccessTokenIntrospector _JwtIntropector = new LocalJwtIntrospector(_MyTotallySecretDemoJwtKey);

  // States
  private Dictionary<long, string> _LoginsPerSessionId = new Dictionary<long, string>();
  private Dictionary<long, TokenIssuingResult> _TokensPerRetrievalCode = new Dictionary<long, TokenIssuingResult>();

  public bool TryAuthenticate(
    string apiClientId, string login, string password, bool noPasswordNeeded, string clientProvidedState,
    out string sessionId, out string message
  ) {

    if (!this.ValidateUser(login)) {
      message = "Wrong credentials";
      sessionId = null;
      return false;
    }

    if (noPasswordNeeded) { 
      message = "Pass-trough authentication successful";
    }
    else {
      if (this.ValidatePassword(login, password)) {
        message = "Password authentication successful";
      }
      else {
        message = "Wrong credentials";
        sessionId = null;
        return false;
      }
    }

    //start the logon session (valid for 1 minute)

    long sid = Snowflake44.Generate();
    sessionId = sid.ToString();

    lock (_LoginsPerSessionId) {
      _LoginsPerSessionId[sid] = login;
    }

    this.CleanupExpiredCodesAndSessions();

    return true;
  }

  public bool TryGetAvailableScopesBySessionId(
    string apiClientId, string sessionId, string[] prefferedScopes,
    out ScopeDescriptor[] availableScopes, out string message
  ) {

    if(TryValidateSessionId(sessionId, out string login)) {
      availableScopes = this.GetAvailableScopes(login, prefferedScopes);
      message = null;
      return true;
    }
    else {
      availableScopes = Array.Empty<ScopeDescriptor>();
      message = "Invalid or expired sessionOtp";
      return false;
    }

  }

  protected ScopeDescriptor[] GetAvailableScopes(
    string loginOrClientId, string[] scopesToSelect
  ) {

    return new ScopeDescriptor[] {
      new ScopeDescriptor {
        Expression = "read", Label = "Read Data",
        Selected = true,//mandatory!
        ReadOnly= true, Invisible= false
      },
      new ScopeDescriptor {
        Expression = "write", Label = "Write Data",
        Selected = scopesToSelect.Contains("write"),
        ReadOnly= false, Invisible= false
      },
    };

  }

  #region " IMPLICIT - FLOW "

  public bool TryValidateSessionIdAndCreateToken(
    string apiClientId, string sessionId, string[] selectedScopes,
    out TokenIssuingResult tokenResult
  ) {

    tokenResult = new TokenIssuingResult();

    if (TryValidateSessionId(sessionId, out string login)) {

      //for security selectedScopes needs be be filtered again because some value could have been injected
      selectedScopes = this.GetAvailableScopes(login, selectedScopes).ToStringArray();

      //this is to keep the demo simple,
      //in a real world scenario not a good idea...
      string subject = login;

      return  _JwtIssuer.RequestAccessToken(
        nameof(DemoOAuthService), subject, "Everybody", selectedScopes, out tokenResult
      );

    }
    else {
      tokenResult.error = "Invalid or expired sessionOtp";
      tokenResult.error_description = "Invalid or expired sessionOtp";
      return false;
    }

  }

  #endregion

  #region " CLIENT CREDENTIAL - FLOW "

  public TokenIssuingResult ValidateClientAndCreateToken(
    string clientId, string clientSecret, string[] selectedScopes
  ) {

    TokenIssuingResult tokenResult = new TokenIssuingResult();

    if (!this.TryValidateApiClientSecret(clientId, clientSecret)) {
      tokenResult.error = "invalid_client";
      tokenResult.error_description = "Unknown client";
      return tokenResult;
    }

    //for security selectedScopes needs be be filtered again because some value could have been injected
    selectedScopes = this.GetAvailableScopes("API_" + clientId, selectedScopes).ToStringArray();

    //this is to keep the demo simple,
    //in a real world scenario not a good idea...
    string subject = "API_" + clientId;

    bool success = _JwtIssuer.RequestAccessToken(
      nameof(DemoOAuthService), subject, "Everybody", selectedScopes, out tokenResult
    );

    return tokenResult;
  }

  #endregion

  #region " CODE - FLOW "

  public bool TryValidateSessionIdAndCreateRetrievalCode(
    string apiClientId, string sessionId, string[] selectedScopes,
    out string code, out string message
  ) {

    bool success = this.TryValidateSessionIdAndCreateToken(
      apiClientId, sessionId, selectedScopes,
      out TokenIssuingResult tokenResult
    );

    if (success) {
      long retrievalCode = Snowflake44.Generate();

      lock (_TokensPerRetrievalCode) {
        //stage the token for retrieval
        _TokensPerRetrievalCode[retrievalCode] = tokenResult;
      }

      code = retrievalCode.ToString();
      message = null;
      return true;
    }
    else {
      code = null;
      message = tokenResult?.error;
      return false;
    }
  }

  public TokenIssuingResult RetrieveTokenByCode(string clientId, string clientSecret, string code) {
    TokenIssuingResult result = new TokenIssuingResult();

    if (!this.TryValidateApiClientSecret(clientId, clientSecret)) {
      result.error = "invalid_client";
      result.error_description = "Unknown client";
      return result;
    }

    lock (_TokensPerRetrievalCode) {

      if (long.TryParse(code, out long codeLong)){

        //code is only valid for 1 minute
        if (Snowflake44.DecodeDateTime(codeLong).AddMinutes(1) > DateTime.UtcNow) {

          if (_TokensPerRetrievalCode.ContainsKey(codeLong)) {

            result = _TokensPerRetrievalCode[codeLong];

            //make sure the code can only be used once
            _TokensPerRetrievalCode.Remove(codeLong);

            return result;  
          }

        }

      }

    }

    result.error = "invalid_code";
    result.error_description = "Invalid Code";
    return result;
  }

  #endregion

  public TokenIssuingResult CreateFollowUpToken(string refreshToken) {
    TokenIssuingResult tokenResult = new TokenIssuingResult();

    tokenResult.error = "invalid_request";
    tokenResult.error_description = "Refresh-Token currently not supported";

    return tokenResult;
  }

  #region " Introspection (RFC7662) "

  public void IntrospectAccessToken(string rawToken, out bool isActive, out Dictionary<string, object> claims) {

    _JwtIntropector.IntrospectAccessToken(rawToken, out isActive, out claims);

    //in addition to that we could check here, if the token was revoked!

  }

  #endregion

  public bool TryValidateApiClient(
    string apiClientId, string apiCallerHost, string redirectUri,
    out string message
  ) {

    if (apiClientId == _MyOAuthClientId) {
      message = "Valid client";
      return true;
    }
    else {
      message = "Unknown client";
      return false;
    }

  }

  public bool TryValidateApiClientSecret(
    string apiClientId, string apiClientSecret
  ) {

    if (apiClientId == _MyOAuthClientId && apiClientSecret == _MyOAuthClientSecret) {
      return true;
    }
    else {
      return false;
    }

  }

  private bool TryValidateSessionId(string sessionId, out string login) {
    lock (_LoginsPerSessionId) {

      if (long.TryParse(sessionId, out long sid)) {

        if (Snowflake44.DecodeDateTime(sid).AddMinutes(1) > DateTime.UtcNow) {

          if (_LoginsPerSessionId.TryGetValue(sid, out login)) {

            return true;
          }
        }
      }
    }

    login = null;
    return false;
  }

  private void CleanupExpiredCodesAndSessions() {

    lock (_LoginsPerSessionId) {
      foreach (long sid in _LoginsPerSessionId.Keys.ToArray()) {
        if (Snowflake44.DecodeDateTime(sid).AddMinutes(1) < DateTime.UtcNow) {
          _LoginsPerSessionId.Remove(sid);
        }
      }
    }

    lock (_TokensPerRetrievalCode) {
      foreach (long code in _TokensPerRetrievalCode.Keys.ToArray()) {
        if (Snowflake44.DecodeDateTime(code).AddMinutes(1) < DateTime.UtcNow) {
          _TokensPerRetrievalCode.Remove(code);
        }
      }
    }

  }

}