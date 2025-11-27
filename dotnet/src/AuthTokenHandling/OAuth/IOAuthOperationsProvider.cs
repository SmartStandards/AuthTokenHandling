using Newtonsoft.Json;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth.OobProviders;
using Security.AccessTokenHandling.OAuth.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling.OAuth {

  public interface IOAuthOperationsProvider {

    #region " Metadata & Config "

    Func<IOAuthOperationsProvider, HttpClient> HttpClientFactory{ get; set; }

    void SetConfigurationValue(string key, string value);
    bool TryGetConfigurationValue(string key, out string value);

    string ProviderInvariantName { get; }

    string ProviderDisplayTitle { get; }

    /// <summary>
    /// Can be a http(s)-url or a data-url (128x128 PNG)
    /// </summary>
    string ProviderIconUrl { get; }

    #endregion

    string GenerateEntryUrlForOAuthCodeGrant(
      string clientId, string redirectUri,
      bool requestRefreshToken, bool requestIdToken,
      string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    );

    [Obsolete("Implicit Grant is deprecated.")]
    string GenerateEntryUrlForOAuthImplicitGrant(
      string clientId, string redirectUri,
      bool requestRefreshToken, bool requestIdToken,
      string state, string[] scopes, Dictionary<string, object> additionalQueryParams = null
    );

    /// <summary>
    /// Will also automatially retrieve the token, if there is a code in the url
    /// (the clientSecret is required for that, otherwise an exception will be thrown)
    /// </summary>
    /// <param name="finalUrlFromAuthFlow"></param>
    /// <param name="clientId"></param>
    /// <param name="clientSecret">
    ///  Optional when the token is present within the url.
    ///  But if a code is present instead of a token, this parameter is required to avaid an Excpetion!
    /// </param>
    /// <param name="result"></param>
    /// <returns></returns>
    bool TryGetTokenFromRedirectedUrl(
      string finalUrlFromAuthFlow,
      string clientId, string clientSecret,
      out TokenIssuingResult result
    );

    /// <summary></summary>
    /// <param name="finalUrlFromAuthFlow"></param>
    /// <param name="code"></param>
    /// <param name="finalUrlWithoutQuery">
    ///  just as convenience, because you may need the clean 'return_uri' again to retrieve the token...
    /// </param>
    /// <returns> true, if a code was found and extracted </returns>
    bool TryGetCodeFromRedirectedUrl(
      string finalUrlFromAuthFlow,
      out string code, out string finalUrlWithoutQuery
    );

    bool TryGetAccessTokenViaOAuthCode(
      string code,
      string clientId, string clientSecret,
      string redirectUriAgain,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    );

    bool TryGetAccessTokenViaOAuthClientCredentials(
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    );

    bool TryGetAccessTokenViaOAuthRefreshToken(
      string refreshToken,
      string clientId, string clientSecret,
      out TokenIssuingResult result,
      Dictionary<string, object> additionalQueryParams = null
    );

    /// <summary> </summary>
    /// <param name="accessToken">the current 'access_token'</param>
    /// <param name="subject">as provided by the endpoint (null, if the validation operation could not be performed) </param>
    /// <param name="scopes">
    ///  as provided by the endpoint (null, if this not provided by the endpoint or if the validation operation could not be performed) 
    ///  NOTE: an empty array means, that a subject was resolved, but explicitely no scopes are associated with it!
    /// </param>
    /// <param name="additionalClaims">
    /// can be empty (will only be null, if the operation failed)
    ///  Common additional claims are e.g. 'email', 'email_verified', 'name', 'picture' (url), ...
    /// </param>
    /// <returns>
    ///   true, if a subject was resolved (also if there are no scopes returned) or
    ///   false, if no subject was resolved / operation could not be performed (endpoint not available, ...)
    /// </returns>
    bool TryResolveSubjectAndScopes(
      string accessToken,
      out string subject,
      out string[] scopes,
      out Dictionary<string, object> additionalClaims
    );

    /// <summary> </summary>
    /// <param name="accessToken">the current 'access_token'</param>
    /// <param name="idToken"> the 'id_token' (if present) - null is allowed!</param>
    /// <param name="subject">as provided by the endpoint (null, if the validation operation could not be performed) </param>
    /// <param name="scopes">
    ///  as provided by the endpoint (null, if this not provided by the endpoint or if the validation operation could not be performed) 
    ///  NOTE: an empty array means, that a subject was resolved, but explicitely no scopes are associated with it!
    /// </param>
    /// <param name="additionalClaims">
    ///  Can be empty (will only be null, if the operation failed).
    ///  Common additional claims are e.g. 'email', 'email_verified', 'name', 'picture' (url), ...
    /// </param>
    /// <returns>
    ///   true, if a subject was resolved (also if there are no scopes returned) or
    ///   false, if no subject was resolved / operation could not be performed (endpoint not available, ...)
    /// </returns>
    bool TryResolveSubjectAndScopes(
      string accessToken, string idToken,
      out string subject, out string[] scopes,
      out Dictionary<string, object> additionalClaims
    );

    /// <summary></summary>
    /// <param name="accessToken"></param>
    /// <param name="isActive"> as provided by the endpoint (also false, if the validation operation could not be performed)</param>
    /// <param name="validUntil"> as provided by the endpoint (null, if this not provided or if the validation operation could not be performed)</param>
    /// <param name="invalidReason"> as provided by the endpoint (null, if this not provided by the endpoint or if the validation operation could not be performed) </param>
    /// <returns>
    ///   true, if the given token has been validated (also for negative outcome) or
    ///   false, if validation operation could not be performed (endpoint not available, ...)
    /// </returns>
    bool TryValidateToken(
      string accessToken,
      out bool isActive,
      out DateTime? validUntil,
      out string invalidReason
    );

    /// <summary></summary>
    /// <param name="capabilityName">
    /// Wellknown capabilities are:
    ///   "introspection"
    ///   "refresh_token"
    ///   "id_token"
    ///   "darkmode_url_param"
    ///   "iframe_allowed"
    /// </param>
    bool HasCapability(string capabilityName);

  }

  public static class OAuthOperationsProviderCommonSetupHelper {

    public const string ProviderDisplayTitle = "provider_display_title";
    public const string AuthorizationEndpoint = "authorization_endpoint";
    public const string TokenEndpoint = "token_endpoint";
    public const string IntrospectionEndpoint = "introspection_endpoint";
    public const string IframeAllowed = "iframe_allowed";
    public const string AutoAddOfflineAccess = "auto_add_offline_access";
    public const string IntrospectionAuth = "introspection_auth";

    public static void ApplyCommonConfigurationValues(
      this IOAuthOperationsProvider provider,
      string providerDisplayTitle,
      string authEndpointUrl,
      string tokenEndpointUrlstring,
      string introspectionEndpointUrl,
      bool supportsIframe = false, bool requestIdToken = true,
      IDictionary<string, string> additionalSettings = null
    ) {

      if (!string.IsNullOrWhiteSpace(introspectionEndpointUrl)) {
        //prepare default
        provider.SetConfigurationValue(IntrospectionAuth, "none");
      }

      if(additionalSettings != null) {
        foreach (KeyValuePair<string, string> kvp in additionalSettings) {
          provider.SetConfigurationValue(kvp.Key, kvp.Value);
        }
      }

      provider.SetConfigurationValue(ProviderDisplayTitle, providerDisplayTitle);
      provider.SetConfigurationValue(AuthorizationEndpoint, authEndpointUrl);
      provider.SetConfigurationValue(TokenEndpoint, authEndpointUrl);
      provider.SetConfigurationValue(IntrospectionEndpoint, introspectionEndpointUrl);
      provider.SetConfigurationValue(IframeAllowed,supportsIframe.ToString());
      provider.SetConfigurationValue(AutoAddOfflineAccess, requestIdToken.ToString());

    }

    public static void ApplyConfigurationValuesFromAuthTokenConfig (
      this IOAuthOperationsProvider provider, AuthTokenConfig config
    ) {
      config.ApplyToOAuthOperationsProvider(provider);
    }

    public static void ApplyToOAuthOperationsProvider(
      this AuthTokenConfig config, IOAuthOperationsProvider provider
    ) {

      if (config.IssueMode == WellknownIssuingModes.OAUTH_CIBA_CODEGRAND) {
      }
      else if (config.IssueMode == WellknownIssuingModes.OAUTH_CIBA_CODEGRAND_HTTPGETONLY) {
        provider.SetConfigurationValue("http_get", "true");
      }
      else {
        throw new NotSupportedException("The given issue mode is not supported by OAuthOperationsProvider: " + config.IssueMode);
      }

      provider.SetConfigurationValue("authorization_endpoint", config.AuthEndpointUrl);

      if (config.AuthEndpointRejectsIframe) {
        provider.SetConfigurationValue("iframe_allowed", "false");
      }
      else {
        provider.SetConfigurationValue("iframe_allowed", "true");
      }

    }

    internal static HttpClient DefaultHttpClientFactory(IOAuthOperationsProvider provider) {

      HttpClientHandler handler = new HttpClientHandler();

      if(provider.TryGetConfigurationValue("retrieve_with_default_credentials", out string value)) {
        if(bool.TryParse(value, out bool enableDefaultCredentials) && enableDefaultCredentials) {
          handler.Credentials = CredentialCache.DefaultCredentials;
          handler.UseDefaultCredentials = true;
          handler.PreAuthenticate = true;
        }
      }
      //handler.Credentials = new NetworkCredential("user", "pwd", "domain");

      handler.AllowAutoRedirect = true;

      HttpClient client = new HttpClient(handler);

      return client;
    }

  }

  public static class ForIOAuthOperationsProvider_Extensions {

    /// <summary> </summary>
    /// <param name="provider"> the extendee </param>
    /// <param name="tokennIssuingResult"></param>
    /// <param name="subject">as provided by the endpoint (null, if the validation operation could not be performed) </param>
    /// <param name="scopes">
    ///  as provided by the endpoint (null, if this not provided by the endpoint or if the validation operation could not be performed) 
    ///  NOTE: an empty array means, that a subject was resolved, but explicitely no scopes are associated with it!
    /// </param>
    /// <param name="additionalClaims">can be empty (will only be null, if the operation failed)</param>
    /// <returns>
    ///   true, if a subject was resolved (also if there are no scopes returned) or
    ///   false, if no subject was resolved / operation could not be performed (endpoint not available, ...)
    /// </returns>
    public static bool TryResolveSubjectAndScopes(
      this IOAuthOperationsProvider provider,
      TokenIssuingResult tokennIssuingResult,
      out string subject, out string[] scopes,
      out Dictionary<string, object> additionalClaims
    ) {

      if(tokennIssuingResult?.access_token == null) {
        subject = null;
        scopes = null;
        additionalClaims = null;
        return false;
      }

      return provider.TryResolveSubjectAndScopes(
        tokennIssuingResult.access_token, tokennIssuingResult.id_token,
        out subject, out scopes, out additionalClaims
      );

    }

    /// <summary>
    /// Will also automatially retrieve the token, if there is a code in the url, 
    /// you need the overload with clientSecret (otherwise an exception will be thrown)
    /// </summary>
    /// <param name="provider"> the extendee </param>
    /// <param name="finalUrlFromAuthFlow"></param>
    /// <param name="clientId"></param>
    /// <param name="result"></param>
    /// <returns></returns>
    public static bool TryGetTokenFromRedirectedUrl(
      this IOAuthOperationsProvider provider,
      string finalUrlFromAuthFlow,
      string clientId,
      out TokenIssuingResult result
    ) {

      return provider.TryGetTokenFromRedirectedUrl(
        finalUrlFromAuthFlow,
        clientId, null,
        out result
      );

    }

  }

}
