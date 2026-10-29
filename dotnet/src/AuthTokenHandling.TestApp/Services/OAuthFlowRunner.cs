using AuthTokenHandling.TestApp.Model;
using Newtonsoft.Json.Linq;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.OAuth.OobProviders;
using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace AuthTokenHandling.TestApp.Services {

  /// <summary>
  /// Plays through interactive and non-interactive OAuth flows based on an 'AuthTokenConfigProfile'.
  /// The 'IOAuthOperationsProvider' is initialized from the 'AuthTokenConfig' (endpoints, display values) and
  /// afterwards overridden by the raw 'ProviderConfiguration' values of the profile.
  /// </summary>
  internal static class OAuthFlowRunner {

    /// <summary>
    /// The supported provider types (key = value of 'OAuthFlowSettings.ProviderType').
    /// </summary>
    public static readonly string[] ProviderTypes = new string[] {
      "generic", "microsoft", "google", "github", "facebook", "apple"
    };

    /// <summary>
    /// Creates and configures the 'IOAuthOperationsProvider' for the given profile.
    /// </summary>
    public static IOAuthOperationsProvider CreateProvider(AuthTokenConfigProfile profile) {

      IOAuthOperationsProvider provider = CreateProviderInstance(profile.OAuth.ProviderType);
      AuthTokenConfig config = profile.Config;

      SetIfPresent(provider, "authorization_endpoint", config.AuthEndpointUrl);
      SetIfPresent(provider, "token_endpoint", config.RetrieveEndpointUrl);
      SetIfPresent(provider, "provider_display_title", config.DisplayLabel);
      SetIfPresent(provider, "provider_icon_url", config.DisplayIconUrl);

      bool isIntrospectionMode = (
        string.Equals(config.ValidationMode, WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(config.ValidationMode, WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY, StringComparison.OrdinalIgnoreCase)
      );
      if (isIntrospectionMode) {
        SetIfPresent(provider, "introspection_endpoint", config.ValidationEndpointUrl);
      }

      if (string.Equals(config.IssueMode, WellknownIssuingModes.OAUTH_CIBA_CODEGRAND_HTTPGETONLY, StringComparison.OrdinalIgnoreCase)) {
        provider.SetConfigurationValue("http_get", "true");
      }

      foreach (KeyValuePair<string, string> entry in profile.OAuth.ProviderConfiguration) {
        if (!string.IsNullOrWhiteSpace(entry.Key)) {
          provider.SetConfigurationValue(entry.Key.Trim(), entry.Value);
        }
      }

      return provider;
    }

    /// <summary>
    /// Returns the effective provider configuration (for display purposes).
    /// </summary>
    public static JObject DescribeProvider(AuthTokenConfigProfile profile) {

      IOAuthOperationsProvider provider = CreateProvider(profile);

      JObject reply = new JObject();
      reply["type"] = provider.GetType().FullName;
      reply["invariantName"] = provider.ProviderInvariantName;
      reply["displayTitle"] = provider.ProviderDisplayTitle;

      JObject configuration = new JObject();
      string[] wellknownKeys = new string[] {
        "authorization_endpoint", "token_endpoint", "introspection_endpoint", "tokeninfo_endpoint", "userinfo_endpoint",
        "introspection_auth", "client_credentials_via_basicauth", "client_credentials_scope", "oidc_enabled",
        "auto_add_offline_access", "http_get", "retrieve_with_default_credentials"
      };
      foreach (string key in wellknownKeys) {
        string value;
        if (provider.TryGetConfigurationValue(key, out value)) {
          configuration[key] = value;
        }
      }
      reply["configuration"] = configuration;

      JObject capabilities = new JObject();
      string[] capabilityNames = new string[] { "introspection", "refresh_token", "id_token", "darkmode_url_param", "iframe_allowed" };
      foreach (string capabilityName in capabilityNames) {
        capabilities[capabilityName] = provider.HasCapability(capabilityName);
      }
      reply["capabilities"] = capabilities;

      return reply;
    }

    /// <summary>
    /// INTERACTIVE: executes the code (or implicit) flow within the embedded browser dialog
    /// ('EmbeddedBrowserOAuthIssuer'). Must be called on the UI thread.
    /// </summary>
    public static JObject RunInteractiveFlow(AuthTokenConfigProfile profile, IWin32Window parentWindow) {

      IOAuthOperationsProvider provider = CreateProvider(profile);
      OAuthFlowSettings flow = profile.OAuth;

      string grantType = "code";
      if (!string.IsNullOrWhiteSpace(flow.GrantType)) {
        grantType = flow.GrantType.Trim().ToLowerInvariant();
      }

      IAccessTokenIssuer issuer = new EmbeddedBrowserOAuthIssuer(
        profile.Config.ClientId,
        profile.Config.ClientSecret,
        provider,
        parentWindow,
        flow.RedirectUri,
        grantType,
        flow.RequestRefreshToken,
        flow.RequestIdToken,
        flow.TryKeepBrowserInvisible
      );

      Dictionary<string, object> claimsToRequest = ToObjectDictionary(profile.Config.AdditionalAuthArgs);
      claimsToRequest["scope"] = FactoryRunner.NormalizeScopes(flow.Scopes ?? string.Empty);
      if (!string.IsNullOrWhiteSpace(flow.State)) {
        claimsToRequest["state"] = flow.State.Trim();
      }

      TokenIssuingResult result;
      bool success = issuer.TryRequestAccessToken(claimsToRequest, out result);

      JObject reply = FactoryRunner.TokenResultToJson(success, result);
      reply["flow"] = "interactive/" + grantType;
      return reply;
    }

    /// <summary>
    /// MANUAL (step 1): generates the entry url for the code flow, which can be opened in an external browser.
    /// </summary>
    public static string GenerateAuthorizeUrl(AuthTokenConfigProfile profile) {

      IOAuthOperationsProvider provider = CreateProvider(profile);
      OAuthFlowSettings flow = profile.OAuth;

      string state = flow.State;
      if (string.IsNullOrWhiteSpace(state)) {
        state = Random.Shared.NextInt64().ToString("x16");
      }

      string[] scopes = SplitScopes(flow.Scopes);

      return provider.GenerateEntryUrlForOAuthCodeGrant(
        profile.Config.ClientId,
        flow.RedirectUri,
        flow.RequestRefreshToken,
        flow.RequestIdToken,
        state,
        scopes,
        ToObjectDictionary(profile.Config.AdditionalAuthArgs)
      );
    }

    /// <summary>
    /// MANUAL (step 2): extracts the token (or the code and exchanges it) from the final redirected url.
    /// </summary>
    public static JObject TokenFromRedirectedUrl(AuthTokenConfigProfile profile, string redirectedUrl) {

      IOAuthOperationsProvider provider = CreateProvider(profile);

      TokenIssuingResult result;
      bool success = provider.TryGetTokenFromRedirectedUrl(
        redirectedUrl, profile.Config.ClientId, profile.Config.ClientSecret, out result
      );

      JObject reply = FactoryRunner.TokenResultToJson(success, result);
      reply["flow"] = "redirected-url";
      return reply;
    }

    /// <summary>
    /// NON-INTERACTIVE: exchanges an authorization code for a token.
    /// </summary>
    public static JObject ExchangeCode(AuthTokenConfigProfile profile, string code) {

      IOAuthOperationsProvider provider = CreateProvider(profile);

      TokenIssuingResult result;
      bool success = provider.TryGetAccessTokenViaOAuthCode(
        code, profile.Config.ClientId, profile.Config.ClientSecret, profile.OAuth.RedirectUri,
        out result, ToObjectDictionary(profile.Config.AdditionalRetrieveArgs)
      );

      JObject reply = FactoryRunner.TokenResultToJson(success, result);
      reply["flow"] = "code-exchange";
      return reply;
    }

    /// <summary>
    /// NON-INTERACTIVE: client credentials flow ('ClientCredentialOAuthIssuer').
    /// </summary>
    public static JObject RunClientCredentialsFlow(AuthTokenConfigProfile profile) {

      IOAuthOperationsProvider provider = CreateProvider(profile);
      IAccessTokenIssuer issuer = new ClientCredentialOAuthIssuer(profile.Config.ClientId, profile.Config.ClientSecret, provider);

      Dictionary<string, object> claimsToRequest = ToObjectDictionary(profile.Config.AdditionalRetrieveArgs);
      string scopes = FactoryRunner.NormalizeScopes(profile.OAuth.Scopes ?? string.Empty);
      if (!string.IsNullOrWhiteSpace(scopes)) {
        claimsToRequest["scope"] = scopes;
      }

      TokenIssuingResult result;
      bool success = issuer.TryRequestAccessToken(claimsToRequest, out result);

      JObject reply = FactoryRunner.TokenResultToJson(success, result);
      reply["flow"] = "client-credentials";
      return reply;
    }

    /// <summary>
    /// NON-INTERACTIVE: refresh token flow.
    /// </summary>
    public static JObject RunRefreshFlow(AuthTokenConfigProfile profile, string refreshToken) {

      IOAuthOperationsProvider provider = CreateProvider(profile);

      TokenIssuingResult result;
      bool success = provider.TryGetAccessTokenViaOAuthRefreshToken(
        refreshToken, profile.Config.ClientId, profile.Config.ClientSecret,
        out result, ToObjectDictionary(profile.Config.AdditionalRetrieveArgs)
      );

      JObject reply = FactoryRunner.TokenResultToJson(success, result);
      reply["flow"] = "refresh-token";
      return reply;
    }

    /// <summary>
    /// Validates a token via the provider ('introspection_endpoint' / 'tokeninfo_endpoint').
    /// </summary>
    public static JObject ValidateViaProvider(AuthTokenConfigProfile profile, string accessToken) {

      IOAuthOperationsProvider provider = CreateProvider(profile);

      bool isActive;
      DateTime? validUntil;
      string invalidReason;
      bool performed = provider.TryValidateToken(FactoryRunner.StripBearer(accessToken), out isActive, out validUntil, out invalidReason);

      JObject reply = new JObject();
      reply["performed"] = performed;
      reply["isActive"] = isActive;

      if (validUntil.HasValue) {
        reply["validUntil"] = validUntil.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
      } else {
        reply["validUntil"] = JValue.CreateNull();
      }

      reply["invalidReason"] = invalidReason;
      return reply;
    }

    /// <summary>
    /// Resolves subject, scopes and additional claims via the provider ('userinfo_endpoint' etc.).
    /// </summary>
    public static JObject ResolveSubject(AuthTokenConfigProfile profile, string accessToken, string idToken) {

      IOAuthOperationsProvider provider = CreateProvider(profile);

      string idTokenToUse = null;
      if (!string.IsNullOrWhiteSpace(idToken)) {
        idTokenToUse = idToken.Trim();
      }

      string subject;
      string[] scopes;
      Dictionary<string, object> additionalClaims;
      bool resolved = provider.TryResolveSubjectAndScopes(
        FactoryRunner.StripBearer(accessToken), idTokenToUse, out subject, out scopes, out additionalClaims
      );

      JObject reply = new JObject();
      reply["resolved"] = resolved;
      reply["subject"] = subject;

      if (scopes == null) {
        reply["scopes"] = JValue.CreateNull();
      } else {
        reply["scopes"] = new JArray(scopes);
      }

      if (additionalClaims == null) {
        reply["additionalClaims"] = JValue.CreateNull();
      } else {
        reply["additionalClaims"] = JObject.FromObject(additionalClaims);
      }

      return reply;
    }

    #region " Helpers "

    /// <summary>
    /// Creates the provider instance for the given type name.
    /// </summary>
    private static IOAuthOperationsProvider CreateProviderInstance(string providerType) {

      string normalized = "generic";
      if (!string.IsNullOrWhiteSpace(providerType)) {
        normalized = providerType.Trim().ToLowerInvariant();
      }

      switch (normalized) {
        case "generic":
          return new GenericOAuthOperationsProvider();
        case "microsoft":
          return new MicrosoftOAuthOperationsProvider();
        case "google":
          return new GoogleOAuthOperationsProvider();
        case "github":
          return new GitHubOAuthOperationsProvider();
        case "facebook":
          return new FacebookOAuthOperationsProvider();
        case "apple":
          return new AppleOAuthOperationsProvider();
        default:
          throw new NotSupportedException($"Unknown provider type '{providerType}'!");
      }

    }

    private static void SetIfPresent(IOAuthOperationsProvider provider, string key, string value) {

      if (!string.IsNullOrWhiteSpace(value)) {
        provider.SetConfigurationValue(key, value.Trim());
      }

    }

    private static string[] SplitScopes(string scopes) {

      if (string.IsNullOrWhiteSpace(scopes)) {
        return new string[0];
      }

      return FactoryRunner.NormalizeScopes(scopes).Split(' ');
    }

    private static Dictionary<string, object> ToObjectDictionary(Dictionary<string, string> source) {

      Dictionary<string, object> target = new Dictionary<string, object>();

      if (source == null) {
        return target;
      }

      foreach (KeyValuePair<string, string> entry in source) {
        target[entry.Key] = entry.Value;
      }

      return target;
    }

    #endregion

  }

}
