using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    // Retrieve Token (OAuth2 Token Endpoint) 
    //
    //  used for grant_type:
    //    * authorization_code (step 2 of auth-code-flow)
    //    * client_credentials (headless api access)
    //    * refresh_token
    //

    [HttpPost(), Produces("application/json")]
    [Route("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public TokenIssuingResult RetrieveToken([FromForm] IFormCollection value) {
      try {

        string grantType = string.Empty;
        string clientId = string.Empty;
        string clientSecret = string.Empty;

        if (value.TryGetValue("grant_type", out StringValues grantTypeValue)) {
          grantType = grantTypeValue.ToString();
        }
        if (value.TryGetValue("client_id", out StringValues clientIdValue)) {
          clientId = clientIdValue.ToString();
        }
        if (value.TryGetValue("client_secret", out StringValues clientSecretValue)) {
          clientSecret = clientSecretValue.ToString();
        }

        if (grantType == "authorization_code") {

          string code = null;
          if (value.TryGetValue("code", out StringValues codeValue)) {
            code = codeValue.ToString();
          }

          TokenIssuingResult result = _AuthService.RetrieveTokenByCode(clientId, clientSecret, code);

          if (!string.IsNullOrWhiteSpace(result.error)) {
            SecLogger.LogError(2079846554883157221L, 73021, "Token retrival (for Client '{clientId}') via code '{code}' failed: {reason}", clientId, code, $"{result.error} - {result.error_description}");
          }
          else {
            SecLogger.LogTrace(2079846554883157222L, 73022, "Token retrival (for Client '{clientId}') via code '{code}' successfull.", clientId, code);
          }

          return result;
        }
        else if (grantType == "client_credentials") {

          string[] requestedScopes = Array.Empty<string>();
          if (value.TryGetValue("scope", out StringValues scopeValue)) {
            requestedScopes = scopeValue.ToString().Split(' ');
          }

          TokenIssuingResult result = _AuthService.ValidateClientAndCreateToken(
            clientId, clientSecret, requestedScopes
          );

          if (!string.IsNullOrWhiteSpace(result.error)) {
            SecLogger.LogError(2079846554883157223L, 73023, "Token retrival (for Client '{clientId}') via client_credentials (scopes: {scopes}) failed: {reason}", clientId, scopeValue.ToString(), $"{result.error} - {result.error_description}");
          }
          else {
            SecLogger.LogTrace(2079846554883157224L, 73024, "Token retrival (for Client '{clientId}') via client_credentials (scopes: {scopes}) successfull.", clientId, scopeValue.ToString());
          }

          return result;
        }
        else if (grantType == "refresh_token") {

          string refreshToken = string.Empty;
          if (value.TryGetValue("refresh_token", out StringValues refTokenValue)) {
            refreshToken = refTokenValue.ToString();
          }

          TokenIssuingResult result = _AuthService.CreateFollowUpToken(
            refreshToken
          );

          string refreshTokenProbe = "[EMPTY]";
          if (!string.IsNullOrWhiteSpace(refreshToken)) {
            if (refreshToken.Length < 16) {
              //short tokens are fully masked
              refreshTokenProbe = new string('*', refreshToken.Length);
            }
            else {
              //longer tokens: only show the last 3 chars
              refreshTokenProbe = "...**********" + refreshToken.Substring(refreshToken.Length - 3);
            }
          }

          if (!string.IsNullOrWhiteSpace(result.error)) {
            SecLogger.LogError(2079846554883157225L, 73025, "Token retrival (for Client '{clientId}') via refresh_token 'refreshTokenProbe' failed: {reason}", clientId, refreshTokenProbe, $"{result.error} - {result.error_description}");
          }
          else {
            SecLogger.LogTrace(2079846554883157226L, 73026, "Token retrival (for Client '{clientId}') via refresh_token 'refreshTokenProbe' successfull.", clientId, refreshTokenProbe);
          }

          return result;
        }
        else {

          SecLogger.LogError(2079846554883157227L, 73027, "Token retrival (for Client '{clientId}') failed: {reason}", clientId, $"Unknown Grant-Type '{grantType}'");
        
          return new TokenIssuingResult {
            error = $"Grant-Type '{grantType}' not supported!",
            error_description = $"Grant-Type '{grantType}' not supported!"
          };
        }
      }
      catch (Exception ex) {
        SecLogger.LogCritical(ex);

        return new TokenIssuingResult {
          error = "Processing Error",
          error_description = ex.Message
        };

      }
    }

    #region " via GET (not standard, but sometimes needed) "

    /// <summary>
    /// This is just a proxy-method which allows the usage of a http-get instead of post.
    /// It is NOT part of the oauth2 standard, but resolved the problem, that browsers
    /// will make CORS problems when a SPA is tying to retrieve a token via post using javascript.
    /// </summary>
    /// <param name="grantType"></param>
    /// <param name="clientId"></param>
    /// <param name="clientSecret"></param>
    /// <param name="code"></param>
    /// <returns></returns>
    [HttpGet(), Produces("application/json")]
    [Route("token")]
    public TokenIssuingResult RetrieveTokenViaGet(
      [FromQuery(Name = "grant_type")] string grantType,
      [FromQuery(Name = "client_id")] string clientId,
      [FromQuery(Name = "client_secret")] string clientSecret,
      [FromQuery(Name = "code")] string code
    ) {
      try {

        var args = new Dictionary<string, StringValues>();

        args["grant_type"] = grantType;
        args["client_id"] = clientId;
        args["client_secret"] = clientSecret;
        args["code"] = code;

        return this.RetrieveToken(new FormCollection(args));
      }
      catch (Exception ex) {

        SecLogger.LogCritical(ex);

        return new TokenIssuingResult {
          error = "Processing Error",
          error_description = ex.Message
        };

      }
    }

    #endregion 

  }

}
