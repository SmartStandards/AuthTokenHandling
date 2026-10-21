#if !NET46

using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Security.AccessTokenHandling.OAuth.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;

namespace Security.AccessTokenHandling {

  public static class CheapOAuthSetupExtensions {

    /// <summary>
    /// Registers the 'Cheap OAuth Server' ("one line, everything works"):
    /// the OAuth2 controller with the Cheap OAuth service, RFC 8414 metadata, RFC 7591 dynamic client registration,
    /// RFC 9728 protected resource metadata (if not registered before) and a token source in the 'AccessTokenManager'
    /// (id: 'CheapOAuthOptions.TokenSourceId', default 'default'), whose introspection is done in-process.
    /// A host-registered 'IAuthPageBuilder' is kept; otherwise a default page builder is used, which shows the
    /// client name and the redirect host on the consent page.
    /// </summary>
    /// <returns>The created service (e.g. to read the retained secret of a grant via 'GrantStore').</returns>
    public static CheapOAuthService AddCheapOAuthServer(this IServiceCollection services, Action<CheapOAuthOptions> configure) {
      if (services == null) {
        throw new ArgumentNullException(nameof(services));
      }
      if (configure == null) {
        throw new ArgumentNullException(nameof(configure));
      }

      CheapOAuthOptions options = new CheapOAuthOptions();
      configure.Invoke(options);
      options.Validate();

      CheapOAuthGrantStore grantStore = new CheapOAuthGrantStore();
      CheapOAuthClientRegistry clientRegistry = new CheapOAuthClientRegistry(options);
      CheapOAuthService service = new CheapOAuthService(options, grantStore, clientRegistry);

      if (!string.IsNullOrWhiteSpace(options.PersistToDir)) {
        CheapOAuthStatePersistence persistence = new CheapOAuthStatePersistence(options.PersistToDir, options.PersistencePassphrase);
        clientRegistry.AttachPersistence(persistence);
        grantStore.AttachPersistence(persistence);
        service.AttachPersistence(persistence);
      }

      services.AddSingleton(options);
      services.AddSingleton(grantStore);
      services.AddSingleton(clientRegistry);
      services.AddSingleton(service);
      services.AddSingleton<IOAuthService>(service);
      services.TryAddSingleton<IAuthPageBuilder>(
        new CheapOAuthAuthPageBuilder(new DefaultAuthPageBuilder(options.LoginPageTitle, null, null), clientRegistry)
      );

      services.AddOAuthServerController();
      IMvcBuilder builder = services.AddMvc();
      builder.ConfigureApplicationPartManager(
        (apm) => apm.FeatureProviders.Add(new CheapOAuthControllerProvider())
      );

      if (options.RegisterProtectedResourceMetadata && WellKnownOAuthProtectedResourceRegistry.GetOptions() == null) {
        services.AddWellKnownOAuthProtectedResourceEndpoint((o) => {
          o.ScopesSupported = options.ScopesSupported;
          o.ApplyApiPermissionPrefixToScopesSupported = true;
          //the Cheap OAuth Server itself is opt-in, so it may enable the challenge for all adapters ("one line, everything works")
          o.EmitChallengeForAllAdapters = true;
        });
      }

      //the token source is created from its config (open detail 4): the factory resolves the own
      //introspection endpoint to the in-process service instead of an HTTP call
      AuthTokenConfig config = CreateSelfDescribingConfig(options);
      IntrospectorFactory.RegisterInProcessIntrospector(config.ValidationEndpointUrl, service);
      AccessTokenManager.ConfigureTokenSupply((c) => {
        c.ApplyFromConfiguration(options.TokenSourceId, config);
      });

      return service;
    }

    /// <summary>
    /// Describes the Cheap OAuth Server as 'AuthTokenConfig' (consumed e.g. by Swagger and MCP discovery).
    /// The '{RequestBaseUrl}' placeholder is resolved by the consumers per request.
    /// </summary>
    private static AuthTokenConfig CreateSelfDescribingConfig(CheapOAuthOptions options) {
      string baseUrl = AccessTokenManager.RequestBaseUrlPlaceholder;
      AuthTokenConfig config = new AuthTokenConfig();
      config.DisplayLabel = options.LoginPageTitle;
      config.IssueMode = WellknownIssuingModes.OAUTH_CIBA_CODEGRAND;
      config.AuthEndpointUrl = baseUrl + "/oauth2/authorize";
      config.RetrieveEndpointUrl = baseUrl + "/oauth2/token";
      config.ValidationMode = WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT;
      config.ValidationEndpointUrl = baseUrl + "/oauth2/introspect";
      if (!string.IsNullOrWhiteSpace(options.SwaggerRedirectPath)) {
        config.ClientId = CheapOAuthOptions.SwaggerClientId;
      }
      return config;
    }

  }

  public sealed class CheapOAuthControllerProvider : IApplicationFeatureProvider<ControllerFeature> {

    internal CheapOAuthControllerProvider() {
    }

    void IApplicationFeatureProvider<ControllerFeature>.PopulateFeature(
      IEnumerable<ApplicationPart> parts, ControllerFeature feature
    ) {
      Type controllerType = typeof(CheapOAuthController);
      if (!feature.Controllers.Any((controller) => controller.AsType() == controllerType)) {
        feature.Controllers.Add(controllerType.GetTypeInfo());
      }
    }

  }

}

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Decorates an 'IAuthPageBuilder', so that the consent page clearly shows which client
  /// (name and redirect host) gets access - protection against phishing via open dynamic client registration.
  /// </summary>
  internal sealed class CheapOAuthAuthPageBuilder : IAuthPageBuilder {

    private readonly IAuthPageBuilder _Inner;
    private readonly CheapOAuthClientRegistry _ClientRegistry;

    public CheapOAuthAuthPageBuilder(IAuthPageBuilder inner, CheapOAuthClientRegistry clientRegistry) {
      _Inner = inner;
      _ClientRegistry = clientRegistry;
    }

    public string GetAuthForm(
      string responseType, string prompt, string login, string state, string clientId, string redirectUri,
      string requestedScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      return _Inner.GetAuthForm(responseType, prompt, login, state, clientId, redirectUri, requestedScopes, viewMode, error);
    }

    public string GetWinAuthForm(
      string responseType, string prompt, string login, string state, string clientId, string redirectUri,
      string requestedScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      return _Inner.GetWinAuthForm(responseType, prompt, login, state, clientId, redirectUri, requestedScopes, viewMode, error);
    }

    /// <summary>
    /// Extends the prompt by the client name and the redirect host.
    /// </summary>
    public string GetScopeConfirmationForm(
      string responseType, string prompt, string otp, string state, string clientId, string redirectUri,
      string requestedScopes, ScopeDescriptor[] availableScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      string clientName = _ClientRegistry.GetClientName(clientId);
      if (string.IsNullOrWhiteSpace(clientName)) {
        clientName = clientId;
      }
      string redirectHost = redirectUri;
      Uri uri;
      if (Uri.TryCreate(redirectUri, UriKind.Absolute, out uri)) {
        redirectHost = uri.Host;
      }
      string extendedPrompt = "Grant access for '" + WebUtility.HtmlEncode(clientName) + "' (" + WebUtility.HtmlEncode(redirectHost) + ")? " + prompt;
      return _Inner.GetScopeConfirmationForm(
        responseType, extendedPrompt, otp, state, clientId, redirectUri, requestedScopes, availableScopes, viewMode, error
      );
    }

    public string GetErrorPage(string message, AuthPageViewModeOptions viewMode) {
      return _Inner.GetErrorPage(message, viewMode);
    }

    public string GetTokenDisplayPage(TokenIssuingResult tokenResult, AuthPageViewModeOptions viewMode) {
      return _Inner.GetTokenDisplayPage(tokenResult, viewMode);
    }

    public string GetCustomPage(string customHtmlBodyTemplate, AuthPageViewModeOptions viewMode) {
      return _Inner.GetCustomPage(customHtmlBodyTemplate, viewMode);
    }

  }

}

#endif
