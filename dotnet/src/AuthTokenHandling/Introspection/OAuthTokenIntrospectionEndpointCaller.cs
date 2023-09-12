using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// https://datatracker.ietf.org/doc/html/rfc7662
  /// </summary>
  public class OAuthTokenIntrospectionEndpointCaller : IAccessTokenIntrospector {

    private Func<string> _EndpointUrlGetter;
    private Func<string> _AuthorizationHeaderGetter;


    public OAuthTokenIntrospectionEndpointCaller(string endpointUrl) : this(()=> endpointUrl) {
    }

    public OAuthTokenIntrospectionEndpointCaller(string endpointUrl, string authorizationHeader) : this(() => endpointUrl, ()=> authorizationHeader) {
    }

    public OAuthTokenIntrospectionEndpointCaller(Func<string> endpointUrlGetter, Func<string> authorizationHeaderGetter = null) {

      _EndpointUrlGetter = endpointUrlGetter;
      _AuthorizationHeaderGetter = authorizationHeaderGetter;

      if (_EndpointUrlGetter is null) {
        throw new ArgumentException($"Parameter '{nameof(endpointUrlGetter)}' must not be null!");
      }

      if (_AuthorizationHeaderGetter is null) {
        _AuthorizationHeaderGetter = () => null;
      }

    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="rawToken"></param>
    /// <param name="isActive"></param>
    /// <param name="claims">
    ///   possible, but OPTIONAL! claims are:
    ///   'scope', 'client_id' ,'username', 'token_type', 'exp', 'iat', 'nbf', 'sub', 'aud', 'iss', 'jti'
    /// </param>
    public void IntrospectAccessToken(
      string rawToken, out bool isActive, out Dictionary<string, object> claims
      ) {

      using (WebClient wc = new WebClient()) {

        string url = _EndpointUrlGetter.Invoke();
        string auth = _AuthorizationHeaderGetter.Invoke();
        if (!string.IsNullOrWhiteSpace(auth)) {
          wc.Headers.Set("Authorization", auth);
        }
        wc.Headers.Set("Content-Type", "application/x-www-form-urlencoded");
        wc.Headers.Set("Accept", "application/json");

        string rawJsonResponse = wc.UploadString(url, "token=" + rawToken);

        var activeResp = JsonConvert.DeserializeObject<IntrospectionEndpointResponse>(rawJsonResponse);
        if (activeResp == null || activeResp.active == false) {
          isActive = false;
          claims = null;
          return;
        }

        isActive = true;
        claims = JsonConvert.DeserializeObject<Dictionary<string, object>>(rawJsonResponse);
        if (claims != null) {
          claims.Remove("active");
        }
        else {
          claims = new Dictionary<string, object>();
        }

      }

    }

    internal class IntrospectionEndpointResponse {
      public bool active = false;
    }

  }

}
