using DistributedDataFlow;
using Logging.SmartStandards;
using Logging.SmartStandards;
using Logging.SmartStandards.AspSupport;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuthServer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web.UJMW;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling.Demo")]

namespace Security {

  public class Startup {

    public Startup(IConfiguration configuration) {
      _Configuration = configuration;
    }

    private static IConfiguration _Configuration = null;
    public static IConfiguration Configuration { get { return _Configuration; } }

    const string _ApiTitle = "AuthTokenHandling-Demo";
    Version _ApiVersion = null;

    public void ConfigureServices(IServiceCollection services) {

      services.AddLogging();

      _ApiVersion = typeof(AccessTokenValidator).Assembly.GetName().Version;

      string outDir = AppDomain.CurrentDomain.BaseDirectory;
      string baseUrl = _Configuration.GetValue<string>("BaseUrl");
      services.AddSmartStandardsLogging(_Configuration, _ApiTitle);

      ////////////////////////////////////////////////////////////////////////////////////////////////////

      services.AddControllers();

      //var svc = new DemoService();
      //services.AddSingleton<IDemoService>(svc);

      //services.AddDynamicUjmwControllers(r => {
      //  r.AddControllerFor<IDemoService>();
      //});

      ////////////////////////////////////////////////////////////////////////////////////////////////////

      DemoOAuthService demoOAuthService  = new DemoOAuthService();

      IAuthPageBuilder authPageBuilder = new DefaultAuthPageBuilder(
        _ApiTitle, baseUrl + "docs/", baseUrl + "docs/"
      );

      services.AddSingleton<IOAuthService>(demoOAuthService);
      services.AddSingleton<IAuthPageBuilder>(authPageBuilder);


      //silent-Auth issuer muss komplett für wtw nutzzbar sein INKL RÜCKMELDUNG von fehlern

      //display funktion muss gehen!!!



      //  der stillle flow der post auch !!!!
      services.AddOAuthServerController();







      //wie validieren wir selbst unsere tokens
      AccessTokenValidator.ConfigureTokenValidation(
        demoOAuthService, //<< auch über unseren service
        (cfg) => {
          //cfg.EnableAnonymousSubject
        }
      );

      //UJMW Controller sollen auch den AccessTokenValidator zur validierung nutzen 
      UjmwHostConfiguration.AuthHeaderEvaluator = AccessTokenValidator.TryValidateHttpAuthHeader;

      ////////////////////////////////////////////////////////////////////////////////////////////////////

      //services.AddCors(opt => {
      //  opt.AddPolicy(
      //    "MyCustomCorsPolicy",
      //    c => c
      //      .AllowAnyOrigin()
      //      .AllowAnyHeader()
      //      .AllowAnyMethod()
      //      .DisallowCredentials()
      //  );
      //});

      services.AddSwaggerGen(c => {

        c.ResolveConflictingActions(apiDescriptions => {
          return apiDescriptions.First();
        });
        c.EnableAnnotations(true, true);

        //c.IncludeXmlComments(outDir + ".......Contract.xml", true);
        //c.IncludeXmlComments(outDir + "........Service.xml", true);
        //c.IncludeXmlComments(outDir + "........WebAPI.xml", true);

        #region bearer

        string getLinkMd = "";
        //if (!string.IsNullOrWhiteSpace(masterApiClientSecret)) {
        //  getLinkMd = " [get one...](../oauth?state=myState&client_id=master&login_hint=API-CLIENT&redirect_uri=/oauth/display)";
        //}

        ////https://www.thecodebuzz.com/jwt-authorization-token-swagger-open-api-asp-net-core-3-0/
        //c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
        //  Name = "Authorization",
        //  Type = SecuritySchemeType.ApiKey,
        //  Scheme = "Bearer",
        //  BearerFormat = "JWT",
        //  In = ParameterLocation.Header,
        //  Description = "API-TOKEN" + getLinkMd
        //});

        //c.AddSecurityRequirement(new OpenApiSecurityRequirement
        //  {    
        //      {
        //            new OpenApiSecurityScheme
        //              {
        //                  Reference = new OpenApiReference
        //                  {
        //                      Type = ReferenceType.SecurityScheme,
        //                      Id = "Bearer"
        //                  }
        //              },
        //              new string[] {}

        //      }
        //  });
        //});



          // Security Definition für OAuth2 Implicit Flow
          c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme {
            Type = SecuritySchemeType.OAuth2,
            Flows = new OpenApiOAuthFlows {
              Implicit = new OpenApiOAuthFlow {
                AuthorizationUrl = new Uri("http://localhost:55202" + baseUrl + "oauth2/authorize"), // deine Auth-URL
                Scopes = new Dictionary<string, string>
                {
                    { "write", "Schreibrechte anfordern" }
                }
              }
            }
          });

          // Security Requirement, damit Swagger UI die Authorisierung anfordert
          c.AddSecurityRequirement(new OpenApiSecurityRequirement
          {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "oauth2"
                    },
                    Scheme = "oauth2",
                    Name = "oauth2",
                    In = ParameterLocation.Header
                },
                new List<string> { "write" }
            }
          });
       

        #endregion

        c.UseInlineDefinitionsForEnums();

        c.SwaggerDoc(
          "OAuth",
          new OpenApiInfo {
            Title = "OAuth",
            Version = "2",
            Description = $"[**DEMO-LOGON**]({baseUrl}oauth2/authorize?response_type=display&redirect_uri=http://localhost&state=dummy&scope=write&login_hint=U_001&client_id=11aa22bb33cc) *(pwd: **U_001!**)*"
            //Contact = new OpenApiContact {
            //  Name = "",
            //  Email = "",
            //  Url = new Uri("")
            //},
          }
        );

        c.SwaggerDoc(
          "ApiV3",
          new OpenApiInfo {
            Title = _ApiTitle + " - API",
            Version = _ApiVersion.ToString(3),
            Description = "NOTE: This is not intended be a 'RESTful' api, as it is NOT located on the persistence layer and is therefore NOT focused on doing CRUD operations! This HTTP-based API uses a 'call-based' approach to known BL operations. IN-, OUT- and return-arguments are transmitted using request-/response- wrappers (see [UJMW](https://github.com/SmartStandards/UnifiedJsonMessageWrapper)), which are very lightweight and are a compromise for broad support and adaptability in REST-inspired technologies as well as soap-inspired technologies!",
            //Contact = new OpenApiContact {
            //  Name = "",
            //  Email = "",
            //  Url = new Uri("")
            //},
          }
        );

      });

    }
    
    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(
      IApplicationBuilder app, IWebHostEnvironment env,
      ILoggerFactory loggerfactory, IHostApplicationLifetime lifetimeEvents
    ) {

      var logFileFullName = _Configuration.GetValue<string>("LogFileName");
      var logDir = Path.GetFullPath(Path.GetDirectoryName(logFileFullName));
      Directory.CreateDirectory(logDir);
      loggerfactory.AddFile(logFileFullName);



      //SmartStandardsTraceLogPipe.InitializeAsLoggerInput();
      //DevLogger.LogMethod = loggerfactory.CreateLogger<DevLogger>();

      //required for the www-root
      app.UseStaticFiles();

      app.UseAmbientFieldAdapterMiddleware();

      if (!_Configuration.GetValue<bool>("ProdMode")) {
        app.UseDeveloperExceptionPage();
      }

      var baseUrl = _Configuration.GetValue<string>("BaseUrl");
      if (_Configuration.GetValue<bool>("EnableSwaggerUi")) {

        app.UseSwagger(o => {
          //warning: needs subfolder! jsons cant be within same dir as swaggerui (below)
          o.RouteTemplate = "docs/schema/{documentName}.{json|yaml}";
          //o.SerializeAsV2 = true;
        });

        app.UseSwaggerUI(c => {

          c.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.List);
          c.DefaultModelExpandDepth(2);
          c.DefaultModelsExpandDepth(2);
          //c.ConfigObject.DefaultModelExpandDepth = 2;

          c.DocumentTitle = _ApiTitle + " - OpenAPI Definition(s)";

          //represents the sorting in SwaggerUI combo-box
          c.SwaggerEndpoint("schema/OAuth.json", "OAuth2 Demo");
          c.SwaggerEndpoint("schema/ApiV3.json", _ApiTitle + " - API v" + _ApiVersion.ToString(3));
      
          c.RoutePrefix = "docs";

          //requires MVC app.UseStaticFiles();
          c.InjectStylesheet(baseUrl + "swagger-ui/custom.css");


          c.OAuthClientId(DemoOAuthService._MyOAuthClientId);
          c.OAuthScopes("write");
          c.OAuthAdditionalQueryStringParams(new Dictionary<string, string> {
            ["login_hint"] = "U_001",
          });

        });

      }

      app.UseHttpsRedirection();
      
      app.UseRouting();

      //CORS: muss zwischen 'UseRouting' und 'UseEndpoints' liegen!
      app.UseCors(p =>
          p.AllowAnyOrigin()
          .AllowAnyMethod()
          .AllowAnyHeader()
      );

      app.UseAuthentication(); //<< WINDOWS-AUTH
      app.UseAuthorization();

      app.UseEndpoints(endpoints => {
        endpoints.MapControllers();
      });

    }

  }

}
