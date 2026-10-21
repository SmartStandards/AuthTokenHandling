using DistributedDataFlow;
using Logging.SmartStandards;
using Logging.SmartStandards.AspSupport;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth.Server;
using System;
using System.IO;
using System.Reflection;
using System.Web.UJMW;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling.Demo")]

namespace Security {

  /// <summary>
  /// Demo host, which shows the 'Cheap OAuth Server' as the simple, directly runnable setup:
  /// one call ('AddCheapOAuthServer') provides the OAuth2 endpoints (authorize/token/introspect, RFC 8414,
  /// RFC 7591, RFC 9728) and registers itself as token source in the 'AccessTokenManager'.
  /// The Swagger UI ('/docs') is provided by the SmartStandards-flavored Swagger extension, which is mirrored
  /// as T4 source snapshot (see 'Swagger/SwaggerSetupExtensions.tt') and takes its security schemes from the
  /// 'AccessTokenManager' - so the 'Authorize' button of the Swagger UI directly uses the Cheap OAuth Server.
  /// </summary>
  public static partial class Program {

    /// <summary>
    /// The API group of the protected demo API (see 'DemoApiController').
    /// </summary>
    public const string DemoApiGroupName = "DemoApi";

    /// <summary>
    /// The scope which is required for the demo API (the token contains it as 'API:demo').
    /// </summary>
    public const string DemoScope = "demo";

    private const string _ApiTitle = "AuthTokenHandling-Demo";

    /// <summary>
    /// Registers the services (Cheap OAuth Server, token validation, Swagger).
    /// </summary>
    static partial void OnConfigureServices(IServiceCollection services, IConfiguration config) {

      services.AddLogging();
      services.AddSmartStandardsLogging(config, _ApiTitle);

      services.AddControllers();

      // 1) the Cheap OAuth Server - demo accounts: 'demo' / 'demo' (may call the demo API), 'guest' / 'guest' (may not)
      services.AddCheapOAuthServer((options) => {
        options.LoginPageTitle = _ApiTitle;
        options.UseFixedAccounts(
          ("demo", "demo", new string[] { DemoScope }),
          ("guest", "guest", new string[] { })
        );
        options.ScopesSupported = new string[] { DemoScope };
      });

      // 2) the token validation is driven by the 'AccessTokenManager' (token source 'default' = the Cheap OAuth Server)
      AccessTokenValidator.ConfigureTokenValidationViaAccessTokenManager();
      AccessTokenManager.MapAnonymous("OAuth");
      AccessTokenManager.MapAnonymous(".well-known");
      AccessTokenManager.RequireScope(DemoScope, DemoApiGroupName);

      // UJMW controllers (if any) are validated in the same way
      UjmwHostConfiguration.AuthHeaderEvaluator = AccessTokenValidator.TryValidateHttpAuthHeader;

      // 3) Swagger (T4 snapshot): the security schemes per API group are taken from the 'AccessTokenManager'
      services.AddSwaggerGenSmartStandardsFlavored(AccessTokenManager.GetTokenSourceConfigsForApiGroup);

    }

    /// <summary>
    /// Configures the HTTP request pipeline (the Swagger middlewares are added by the startup filter of the Swagger extension).
    /// </summary>
    static partial void OnRunApplication(
      WebApplication app, IConfiguration config, IServiceProvider services,
      IWebHostEnvironment environment, IHostApplicationLifetime lifetime
    ) {

      app.UseAmbientFieldAdapterMiddleware();

      ILoggerFactory loggerfactory = services.GetRequiredService<ILoggerFactory>();

      string logFileFullName = config.GetValue<string>("LogFileName");
      string logDir = Path.GetFullPath(Path.GetDirectoryName(logFileFullName));
      Directory.CreateDirectory(logDir);
      loggerfactory.AddFile(logFileFullName);

      //required for the www-root
      app.UseStaticFiles();

      if (!config.GetValue<bool>("ProdMode")) {
        app.UseDeveloperExceptionPage();
      }

      app.UseRouting();

      //CORS: must be located between 'UseRouting' and 'UseEndpoints'!
      app.UseCors((policy) => {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
      });

      app.UseAuthorization();

      app.MapControllers();

    }

  }

}
