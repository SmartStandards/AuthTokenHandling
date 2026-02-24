using DistributedDataFlow;
using Logging.SmartStandards;
using Logging.SmartStandards.AspSupport;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth.Server;
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
        _ApiTitle, baseUrl + "docs/", baseUrl + "docs/",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAOwgAADsIBFShKgAAACRRJREFUeF7tnFuMG+UZhkNpK1ApCGhz0RapqjhIRai0vWgFF5VAAVEf93RFw6FSV4CIqiigJNpdj8f2eA/OkrR3lbipWlX0AEQka3vXe6CEZBMKUoUitRQpUkuBQKCAlAsIFcP3jb9ZJetZz3qO/8TvI73yZOef73fmfefwz8FbAAAAAAAAAAAA0DOjv3n5S6nJw1ePaCtXyJ9AP5A3lgazxtJTmcrCa5lS4/1Maf6tbGXhaNZYLuTKz14nzcDFRmr80A1k/MrQvmMmKz+5YuaMJTNXXTYHpo+Yw0+cMPPV5f+l9flHZBFwsfBT7fCtZPRbQ7OrJm3xpKaj8pPL5tDscZqen5RFQdKxzDeW3hmcOWJm9EaH6etFhwMrBLQnmJISIKn0ar6tbJlDsIoQJBmv5ttCCBKMX/NtIQQJJCjzbSEECSJo820hBAkgLPNtIQQKE7b5thACBYnKfFsIgUJEbb4thEABgjF/48vCbkIIYsSf+Q3rBhDfEBqg5QdrR02rjocwIAQx4Nf8wZkXzXRp/nS61DTSleYQGT+aKc83B6ZfMLOVlsMy3YUQRIhf89mobGXxpbsc7vvnyguPcThyxqLDst2FEERAUObfueeZa6VkB+lifedgDSFQjijMt0EIFCNK820QAkWIw3wbhCBmfJlP7Xl4l/Novg1CEBP+tnx+tu952vJbr6e1574mJT2DEESMX/NZPJxLFev3SknfIAQREYT57Ys5jXM5rfFtKRsICEHIsGFk3tt+zGfJ1bxzKa31HSkdGAhBiGT0ZmuYn8n3Yb4tPgFMleo/l9KBghCEQFqv38k3ZjJl73fnzhe/9ZM1Wv9JVQ59U7oIFIQgYNJ640leKU4rzJNoL8Ingllj8WRWO/gN6SZQEIIAoZO2lwem/+q4sjyLQsC3fBECxfmJtvJFMutfPHZ3WlG+lIAQ8HlPWp/r5xCYl9Ah4NWBqYD3ALZUDwGNWoafoJPfYv1hKdd/ZIqNv7BJTisoEEUVAj7v8PBQCb+VnC23zg5o9W9Juf4iU6r/LNCTQCdFEQK9+djAzAvUX6+jmYb1+wT0qUup/mJ49tjl6VLjdesiEK0M55UUgCIIQUZvzltDWqf+u4gfSaPvd4JKXNKu1GdktLk7rF/tqC7TCkluCOi7P8AXohz77qJcdYlOBpuns48f/KqU6j9S2tx9fDKY5BBkS41sew/Q22EgZ1AASs0P7tKa10ip/iRVrN8/MPV8YkNAJ4Ma13Xss4t470d7gFMj2skvS6n+Jakh2KY9vTVTab2Zt763Q39dNFQ7xnuAg1IKJC0EqT2Hr85VWsd5KOjl+/J3oD3AkJQDTFJCwObTsqvD1lC2x+/JfVuXhBurIyN/ulRKAhvVQ+DX/MHpI/R/W3w3VVq4QUqC9agaAr/m89ifhn9nUhOHfyglwUaoFgKYHzI7duy4UibXiCMEuXKz4z1CftoY5odIoVDQp6amXtM0reO5vihD0L65s/jvTKk+mq+2bsxozevTxYXtucriP9pX+2B+4JDpe6anp81arWaWSqVTpJtk1hpRhoAv0LSHds1zNE7/hO9X5KlvntfRvptgvju2+WS6SdPm/v37zWKx+CpNd1wdiywEIr7N277V6+G5RZjvznrzq9WqWalUzuq6nqLZjnfIog6BJ8F8dzYyn6bvkCYbonQIYL47vZg/MTFx+/j4+M3yzzWUDAHMd6cX88fGxm6jeR+Xy+U3aX58o4PNCOa748H8D7gNDQ95mVPKhgDmu+PF/MnJSastS5ZVLwQw3x0yzbP5NCS0xNPKhQDmu0Nm+TZfyRDAfHfIpMDMt8XzYg8BzHeHzAncfFvcJrYQwHx3yJTQzLfFbSMPAcx3h8wI3XxbvExkIYD57pAJkZlvi5c9LwTXS/k1AgkBzHeHVn7k5tviGnwrmab5imHHSxa+QgDz3aGV7mg+GR26+Szul/un6TLVdHzJwlMIYL47Kpg/MzPD02PtXjbGDkH7JQ6XEJD5/CAIzO9Cksy34XcR85PLn7XfSnYwnlWet37Fg8x/G+ZvQBLNt7lHn9uWq66c5JczhvYdNfnlVH4MjH+zaGjfanvLN5bnU+OH8Ny+E2Gbz/XYXO7DSTzPq/k2P975x8tpC9+eNZaeylYW/s6/VUBb/t+yldaT+criPdIMrCdM83Vdt2790vRLpDHSL2i50fWimg/RZ166CQS8obsJaKWHuuXLff9p0zT78xczVCZs87ktfa5ICaASYZvP4vrU/j4pA1QhCvNZvAydA2yTUkAFejGf5ns2nyUBuFvKgbjp1fxyufyhV/NZCIBCRG0+CwFQhDjMZyEAChCX+SwEIGbCNp9qWRd6NtKBAwe4Vlq6AFESpvm0VVtjfJp+l7RAyzxHn4fWi/qbo3k/kG5AVNBKD9V82bX/mtpvlTJAFcI0n8W1yfzfSwmgEmGbz1s/LfMptf+ulAGqELb5LKrH7U/v2rXrK1IKqEAU5rM4APT531qthgCoQlTmsyQA/Jj2FVISxEmU5rMQAIWI2nwWAqAIcZjPQgAUoFAo7OanZ23zDcMI1HwZ6jmK61CbMwhATJD5I2w+m8Fm8SeZf2ZiYuJH0mSNXs1n4/n6vdT+iJb5kD4vEM3jv/8To4AYoBX/BTLhFTaJPi2xWaR3xsfHvyfNLLyYz21pr/IHmr6dltm6d+/er9Pe5QLx3+lwcy2e8I0BWvlXkt6jLf4C8/j4z2bTvNukXc+7fQnVr6yOgJqQSVc5BYBNlmPze6Rf8mcv5nM92urfoPaXSVdARTgAZNiZ9QFgsdl8OLCP4Zs1n8WjCfr8s3QDVKVbAPxIAvBb6QaoSsgB+J10A1QFAehzOAB0bO84CfQrBCAh7N69m/cA7yMAfcrIyMiltAc4KUO+wIQAJAgy6uHZ2VlrqHe+iX4kv8rxtHQBVIf2AjN0GPg//4YeXwXky7jrTd2s+IYS16Gaj0p5kATIuFsoBBqZ/wqbyFtxr2GwlysUCp5/kwcoABn5fVJPYbDb0TTMv5jYTBh4FAHz+wCnMLAMwzhL5u+UZqAf4DDQlj9Ke4MH6YSv4yfYAQAAAAAAAAAAAAAAAAAAAACBsWXL5/TVBFPdsFweAAAAAElFTkSuQmCC"
      );

      services.AddSingleton<IOAuthService>(demoOAuthService);
      services.AddSingleton<IAuthPageBuilder>(authPageBuilder);


      //silent-Auth issuer muss komplett für wtw nutzzbar sein INKL RÜCKMELDUNG von fehlern

      //display funktion muss gehen!!!



      //  der stillle flow der post auch !!!!
      services.AddOAuthServerController();


      if (_Configuration.GetValue<bool>("EnableWindowsAuth")) {
        services.AddAuthentication().AddNegotiate();
        services.AddAuthorization(options => {
          options.AddPolicy("WindowsOnly", policy => {
            policy.AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
            policy.RequireAuthenticatedUser();
          });
        });
      }



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
            Description = $"[**DEMO-PASS-TROUGH**]({baseUrl}oauth2/sso/authorize?response_type=display&redirect_uri=http://localhost&state=dummy&scope=write&login_hint=WINAUTH&client_id=11aa22bb33cc) | [**DEMO-LOGON**]({baseUrl}oauth2/authorize?response_type=display&redirect_uri=http://localhost&state=dummy&scope=write&login_hint=U_001&client_id=11aa22bb33cc) *(pwd: **U_001!**)*"
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


          c.OAuthClientId(DemoOAuthService._OurDemoOAuthClientId);
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
