using Security.AccessTokenHandling.OAuthServer;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Runs the OAuth-Flow silently, which is only possible if the server is supporting that!
  /// A common usecase is when having passtrough Windows-Authentication,
  /// or another self-issued api PAT token to be used when requesting a user-token via oauth.
  /// </summary>
  public class OAuthBackgroundAuthenticator : IAccessTokenIssuer {

    private ClaimCustomizerDelegate _ClaimCustomizer = null;

    private Func<string> _EntryUrlGetter;
    private Func<string> _RetrivalUrlGetter;
    private Func<string> _AuthorizationHeaderGetter;
    private string _DummyRedirectUrl;

    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private string _OAuthClientSecret;
    private string _OAuthClientId;

    //non-standard behaviour (only for configurative special case)
    internal bool UseHttpGet { get; set; } = false;

    public OAuthBackgroundAuthenticator(
      string oAuthClientId, string oAuthClientSecret, string dummyRedirectUrl,
      string entryUrl, string retrivalUrl,
      ClaimCustomizerDelegate claimCustomizer = null
    ) :
      this(oAuthClientId, oAuthClientSecret, dummyRedirectUrl, () => entryUrl, () => retrivalUrl, null, claimCustomizer) {
    }

    public OAuthBackgroundAuthenticator(
      string oAuthClientId, string oAuthClientSecret, string dummyRedirectUrl,
      string entryUrl, string retrivalUrl, string authorizationHeader,
      ClaimCustomizerDelegate claimCustomizer = null
    ) :
      this(oAuthClientId, oAuthClientSecret, dummyRedirectUrl, () => entryUrl, () => retrivalUrl, () => authorizationHeader, claimCustomizer) {
    }

    public OAuthBackgroundAuthenticator(
      string oAuthClientId, string oAuthClientSecret, string dummyRedirectUrl,
      Func<string> entryUrlGetter, Func<string> retrivalUrlGetter, Func<string> authorizationHeaderGetter = null,
      ClaimCustomizerDelegate claimCustomizer = null
    ) {

      _OAuthClientId = oAuthClientId;
      _OAuthClientSecret = oAuthClientSecret;
      _EntryUrlGetter = entryUrlGetter;
      _RetrivalUrlGetter = retrivalUrlGetter;
      _AuthorizationHeaderGetter = authorizationHeaderGetter;
      _ClaimCustomizer = claimCustomizer;
      _DummyRedirectUrl = dummyRedirectUrl;

      if (entryUrlGetter is null) {
        throw new ArgumentException($"Parameter '{nameof(entryUrlGetter)}' must not be null!");
      }
      if (retrivalUrlGetter is null) {
        throw new ArgumentException($"Parameter '{nameof(retrivalUrlGetter)}' must not be null!");
      }
      if (_AuthorizationHeaderGetter is null) {
        _AuthorizationHeaderGetter = () => null;
      }

    }

    public bool TryRequestAccessToken(out TokenIssuingResult result) {
      return this.TryRequestAccessToken(null, out result);
    }

    public bool TryRequestAccessToken(Dictionary<string, object> claimsToRequest, out TokenIssuingResult result) {
      result = new TokenIssuingResult();  
      if (claimsToRequest == null) {
        claimsToRequest = new Dictionary<string, object>();
      }
      var claimsToUse = new Dictionary<string, object>();
      if (_ClaimCustomizer != null) {
        bool merge = false;
        _ClaimCustomizer.Invoke(claimsToRequest, claimsToUse, ref merge);
        if (merge) {
          if (claimsToUse.Count == 0) {
            claimsToUse = claimsToRequest;
          }
          else {
            foreach (var customClaim in claimsToRequest) {
              object value = customClaim.Value;
              //special case: scope's needs to be merged!
              if (customClaim.Key == "scope" && customClaim.Value != null && claimsToUse.ContainsKey("scope")) {
                var scopesToUse = claimsToUse["scope"].ToString().Split(' ');
                var customScopes = customClaim.Value.ToString().Split(' ');
                value = string.Join(" ", scopesToUse.Union(customScopes).Where((s) => !string.IsNullOrWhiteSpace(s)).Distinct());
              }
              if (value == null) {
                if (claimsToUse.ContainsKey(customClaim.Key)) {
                  claimsToUse.Remove(customClaim.Key);
                }
              }
              else {
                claimsToUse[customClaim.Key] = value;
              }
            }
          }
        }
      }
      else {
        //passtrough
        claimsToUse = claimsToRequest;
      }

      //prepare urls

      string state = Guid.NewGuid().ToString().ToLower().Replace("-", "");

      claimsToUse["response_type"] = "code";
      claimsToUse["redirect_uri"] = _DummyRedirectUrl;
      claimsToUse["state"] = state;
      claimsToUse["client_id"] = _OAuthClientId;

      if (claimsToUse.ContainsKey("sub") && !claimsToUse.ContainsKey("login_hint")) {
        //subject als login-hinweis hinterlegen (falls vorhanden)
        claimsToUse["login_hint"] = claimsToUse["sub"];
        claimsToUse.Remove("sub");
      }

      string entryUrl = this.ApplyUrlQueryParams(_EntryUrlGetter.Invoke(), claimsToUse);
      string arrivalUrl = null;
      try {
        arrivalUrl = this.GetFinalRedirect(entryUrl, _DummyRedirectUrl);
      }
      catch (Exception ex) {
        //throw new Exception($"OAuth-Flow failed during authorize: " + ex.Message);
        result.error = $"OAuth-Flow failed during authorize: " + ex.Message;
        return false;
      }
      string retrievedCode = this.PickFromUrl(arrivalUrl, "code");
      string returnedState = this.PickFromUrl(arrivalUrl, "state");
      string error = this.PickFromUrl(arrivalUrl, "error");
      if (string.IsNullOrWhiteSpace(retrievedCode)) {
        if (!string.IsNullOrWhiteSpace(error)) {
          //throw new Exception($"OAuth-Flow failed during authorize: " + error);
          result.error = $"OAuth-Flow failed during authorize: " + error;
          return false;
        }
        else {
          //throw new Exception($"OAuth-Flow failed during authorize: There is no 'code' within the query-params of url " + arrivalUrl);
          result.error = $"OAuth-Flow failed during authorize: There is no 'code' within the query-params of url " + arrivalUrl;
          return false;
        }
      }

      try {
       
        this.RetrieveTokenViaCode(
          retrievedCode, this.UseHttpGet,
          out string token, out string refreshToken, out string idToken, out string retError
        );

        if (!string.IsNullOrWhiteSpace(token)) {
          result.token_type = "Bearer";
          result.access_token = token;
          return true;
        }
        else { 
          if (!string.IsNullOrWhiteSpace(retError)) {
            //throw new Exception(retError);
            result.error = retError;
            return false;
          }
          else {
            //throw new Exception("There is no 'code' within the query-params of url " + arrivalUrl);
            result.error = "There is no 'code' within the query-params of url " + arrivalUrl;
            return false;
          }
        }
      }
      catch (Exception ex) {
        //throw new Exception($"OAuth-Flow failed during token retrival: " + ex.Message);
        result.error = "OAuth-Flow failed during token retrival: " + ex.Message;
        return false;
      }

    }

    protected void RetrieveTokenViaCode(
      string authorizationCode, bool useHttpGet,
      out string accessToken, out string refreshToken, out string idToken,
      out string error
    ) {

        using (WebClient wc = new WebClient()) {
          //HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
          wc.UseDefaultCredentials = true;

          string rawJsonResponse;   
          string retrivalUrl = _RetrivalUrlGetter.Invoke();

          wc.Headers.Set("Accept", "application/json");
          if (!useHttpGet) {
            wc.Headers.Set("Content-Type", "application/x-www-form-urlencoded");
            //wc.Headers.Set("Access-Control-Allow-Origin", window.location.origin);
            //wc.Headers.Set("Referrer-Policy", 'origin-when-cross-origin');
            rawJsonResponse = wc.UploadString(
              retrivalUrl,
              "client_id=" + _OAuthClientId + 
              "&client_secret=" + _OAuthClientSecret + 
              "&code=" + authorizationCode +
              "&grant_type=authorization_code" + 
              "&redirect_uri=" + _DummyRedirectUrl
            );
          }
          else {
            var args = new Dictionary<string, object>();
            args["client_id"] = _OAuthClientId;
            args["client_secret"] = _OAuthClientSecret;
            args["code"] = authorizationCode;
            args["grant_type"] = "authorization_code";
            args["redirect_uri"] = _DummyRedirectUrl;
            retrivalUrl = this.ApplyUrlQueryParams(retrivalUrl, args);
            rawJsonResponse = wc.DownloadString(retrivalUrl);
          }

          refreshToken = null;
          idToken = null;
          accessToken = this.PickJsonValue("access_token", rawJsonResponse);
          if (string.IsNullOrWhiteSpace(accessToken)) {
            accessToken = null;
            error = this.PickJsonValue("error_description", rawJsonResponse);
            if (string.IsNullOrWhiteSpace(error)) {
              error = this.PickJsonValue("error", rawJsonResponse);
            }
            if (!string.IsNullOrWhiteSpace(error)) {
              error = "No token received! Server says: " + error;
            }
            else {
              error = "No token received!";
            }
          }
          else {
            idToken = this.PickJsonValue("id_token", rawJsonResponse);
            refreshToken = this.PickJsonValue("refresh_token", rawJsonResponse);
          }

          error = null;
        }
    }

    #region " Helpers "

    private string ApplyUrlQueryParams(string baseUrl, Dictionary<string, object> queryParams) {
      var sb = new StringBuilder(1000);

      int splitterIdx = baseUrl.IndexOf('?');
      if (splitterIdx < 0) {
        sb.Append(baseUrl);
      }
      else {
        sb.Append(baseUrl.Substring(0, splitterIdx));
        string[] queryParts = baseUrl.Substring(splitterIdx + 1).Split('&');
        foreach (string part in queryParts) {
          int idx = part.IndexOf('=');
          if (idx > 0) {
            string key = part.Substring(0, idx);
            string value  = part.Substring(idx + 1);
            if (!queryParams.ContainsKey(key)) {
              queryParams[key] = value;
            }
          }
        }
      }

      if (queryParams.Any()) {
        bool first = true;
        foreach (var kvp in queryParams) {
          if (first) {
            sb.Append('?');
          }
          else {
            sb.Append('&');
          }
          sb.Append(kvp.Key);
          sb.Append("=");
          sb.Append(kvp.Value);
        }
      }

      return sb.ToString();
    }


    //HACK: handgedengelt, dafür brauchen wir keine lib wie newtonsoft...
    private string PickJsonValue(string key, string rawJson) {
      int foundAt = rawJson.IndexOf("\"" + key + "\":");
      if (foundAt >= 0) {
        string startsWithvalue = rawJson.Substring(foundAt + key.Length + 3).Trim();
        if (startsWithvalue.StartsWith("null")) {
          return null;
        }
        else if (startsWithvalue.StartsWith("\"")) {
          return startsWithvalue.Substring(1, startsWithvalue.IndexOf("\"", 1) - 1);
        }
        else if (startsWithvalue.StartsWith("{")) {
          return null;
        }
        else if (startsWithvalue.StartsWith("[")) {
          return null;
        }
        else { //number
          startsWithvalue = startsWithvalue.Replace("}", ",").Replace(Environment.NewLine, "");
          return startsWithvalue.Substring(0, startsWithvalue.IndexOf(",", 1));
        }
      }
      else {
        return null;
      }
    }

    private string GetFinalRedirect(string url, string endUrl) {
      if (string.IsNullOrWhiteSpace(url))
        return url;

      int maxRedirCount = 8;  // prevent infinite loops
      string newUrl = url;
      do {
        HttpWebRequest req = null;
        HttpWebResponse resp = null;
        try {
          if (url.StartsWith(endUrl) & (url.Contains("?code=") || url.Contains("?token="))) {
            return url;
          }
          req = (HttpWebRequest)HttpWebRequest.Create(url);
          req.Method = "GET";
          req.AllowAutoRedirect = false;
          req.UseDefaultCredentials = true;
          resp = (HttpWebResponse)req.GetResponse();
          switch (resp.StatusCode) {
            case HttpStatusCode.OK:
              return newUrl;
            case HttpStatusCode.Redirect:
            case HttpStatusCode.MovedPermanently:
            case HttpStatusCode.RedirectKeepVerb:
            case HttpStatusCode.RedirectMethod:
              newUrl = resp.Headers["Location"];
              if (newUrl == null)
                return url;

              if (newUrl.IndexOf("://", System.StringComparison.Ordinal) == -1) {
                // Doesn't have a URL Schema, meaning it's a relative or absolute URL
                Uri u = new Uri(new Uri(url), newUrl);
                newUrl = u.ToString();
              }
              break;
            default:
              return newUrl;
          }
          url = newUrl;
        }
        catch (WebException ex) {
          // Return the last known good URL
          return newUrl;
        }
        catch (Exception ex) {
          return newUrl;
        }
        finally {
          if (resp != null)
            resp.Close();
        }
      } while (maxRedirCount-- > 0);

      return newUrl;
    }

    private string PickFromUrl(string url, string key) {
      return (
        (url + "?").
        Split('?')[1].
        Split('&').
        Where((x) => x.StartsWith(key + "=", StringComparison.CurrentCultureIgnoreCase)).
        Select((x) => x.Substring(x.IndexOf("=") + 1)).
        FirstOrDefault()
      );
    }

    #endregion

  }

}
