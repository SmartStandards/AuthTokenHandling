using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Security.AccessTokenHandling.OAuthServer;
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
    /// </summary>
    /// <param name="services"></param>
    public static void AddOAuthServerController(this IServiceCollection services) {

      IMvcBuilder builder = services.AddMvc(); //Pkg: Microsoft.AspNetCore.Mvc
  
      builder.ConfigureApplicationPartManager(
        (apm) => apm.FeatureProviders.Add(new OAuthControllerProvider())
      );

    }

  }

  public sealed class OAuthControllerProvider : IApplicationFeatureProvider<ControllerFeature> {

    internal OAuthControllerProvider() {
    }

    void IApplicationFeatureProvider<ControllerFeature>.PopulateFeature(
      IEnumerable<ApplicationPart> parts, ControllerFeature feature
    ) {

      Type controllerType = typeof(OAuthServiceController);
      feature.Controllers.Add(controllerType.GetTypeInfo());

    }

  }

}
