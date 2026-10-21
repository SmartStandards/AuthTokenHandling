using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Security.AccessTokenHandling.OAuth.Server;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

namespace Security.AccessTokenHandling {

  public static class SetupExtensions {

    /// <summary>
    /// NOTE: this will also require injectable implementations of 'IOAuthService' and 'IAuthPageBuilder'!
    /// Registers the 'OAuth2Controller' (incl. RFC 7591 client registration) and the 'OAuthDiscoverController'
    /// (RFC 8414 authorization server metadata).
    /// </summary>
    /// <param name="services"></param>
    public static void AddOAuthServerController(this IServiceCollection services) {

      IMvcBuilder builder = services.AddMvc(); //Pkg: Microsoft.AspNetCore.Mvc
  
      builder.ConfigureApplicationPartManager(
        (apm) => apm.FeatureProviders.Add(new OAuthControllerProvider())
      );

    }

    /// <summary>
    /// Registers the OAuth Protected Resource Metadata endpoint and configures Bearer challenges to reference it.
    /// </summary>
    /// <param name="services">The service collection to register with.</param>
    /// <param name="configure">The protected-resource metadata configuration.</param>
    public static void AddWellKnownOAuthProtectedResourceEndpoint(
      this IServiceCollection services,
      Action<WellKnownOAuthProtectedResourceOptions> configure
    ) {
      if (services == null) {
        throw new ArgumentNullException(nameof(services));
      }
      if (configure == null) {
        throw new ArgumentNullException(nameof(configure));
      }

      WellKnownOAuthProtectedResourceOptions options = new WellKnownOAuthProtectedResourceOptions();
      configure.Invoke(options);
      options.Validate();

      // Relative URLs are qualified on-demand from the incoming request (by the controller
      // and by the 'EvaluateBearerTokenAttribute' when emitting the 401 challenge).
      WellKnownOAuthProtectedResourceRegistry.Register(options);

      // OPT-IN wiring of the 401 challenge for all adapters (UJMW hook, WCF inspector, EvaluateBearerTokenAttribute).
      // A builder configured explicitly by the host is never overwritten.
      if (options.EmitChallengeForAllAdapters && !AccessTokenValidator.IsChallengeHeaderBuilderConfigured) {
        AccessTokenValidator.ConfigureChallengeHeaders(
          WellKnownOAuthProtectedResourceRegistry.BuildChallengeHeaders
        );
      }

      // Allows addressing '.well-known/oauth-protected-resource' on any path level (e.g. '/foo/.well-known/...').
      services.AddTransient<IStartupFilter, WellKnownOAuthProtectedResourcePathStartupFilter>();

      IMvcBuilder builder = services.AddMvc(); //Pkg: Microsoft.AspNetCore.Mvc
      builder.ConfigureApplicationPartManager(
        (apm) => apm.FeatureProviders.Add(new WellKnownOAuthProtectedResourceControllerProvider())
      );

    }

  }

  public sealed class OAuthControllerProvider : IApplicationFeatureProvider<ControllerFeature> {

    internal OAuthControllerProvider() {
    }

    void IApplicationFeatureProvider<ControllerFeature>.PopulateFeature(
      IEnumerable<ApplicationPart> parts, ControllerFeature feature
    ) {

      Type controllerType = typeof(OAuth2Controller);
      if (!feature.Controllers.Any((controller) => controller.AsType() == controllerType)) {
        feature.Controllers.Add(controllerType.GetTypeInfo());
      }

      // RFC 8414 metadata (capabilities delegated to 'IOAuthService') - always part of the OAuth server
      Type discoverControllerType = typeof(WellKnownOAuthDiscoverController);
      if (!feature.Controllers.Any((controller) => controller.AsType() == discoverControllerType)) {
        feature.Controllers.Add(discoverControllerType.GetTypeInfo());
      }

    }

  }

  public sealed class WellKnownOAuthProtectedResourceControllerProvider : IApplicationFeatureProvider<ControllerFeature> {

    internal WellKnownOAuthProtectedResourceControllerProvider() {
    }

    void IApplicationFeatureProvider<ControllerFeature>.PopulateFeature(
      IEnumerable<ApplicationPart> parts, ControllerFeature feature
    ) {

      Type controllerType = typeof(WellKnownOAuthProtectedResourceController);
      if (!feature.Controllers.Any((controller) => controller.AsType() == controllerType)) {
        feature.Controllers.Add(controllerType.GetTypeInfo());
      }

    }

  }

}
