using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security {

  /// <summary>
  /// Tests for the automatic detection of the Windows pass-through (Single-Sign-On) availability.
  /// </summary>
  [TestClass]
  public class PassThroughAvailabilityTests {

    /// <summary>
    /// Without any Windows authentication in the host, pass-through is not offered and the SSO endpoint
    /// renders an error page instead of throwing ('WindowsOnly' policy not found).
    /// </summary>
    [TestMethod]
    public void Auto_WithoutWindowsAuth_NotAvailableAndErrorPage() {
      OAuth2Controller controller = CreateController(PassThroughMode.Auto, false, false);

      Assert.IsFalse(controller.IsPassThroughAvailable());

      bool success = controller.TryEnsurePassThroughIdentity(new AuthPageViewModeOptions(), out string userName, out ActionResult result);
      Assert.IsFalse(success);
      Assert.IsInstanceOfType(result, typeof(ContentResult));
    }

    /// <summary>
    /// A registered 'Negotiate' scheme makes pass-through available; an anonymous request is challenged.
    /// </summary>
    [TestMethod]
    public void Auto_WithNegotiateScheme_AvailableAndChallenged() {
      OAuth2Controller controller = CreateController(PassThroughMode.Auto, true, false);

      Assert.IsTrue(controller.IsPassThroughAvailable());

      bool success = controller.TryEnsurePassThroughIdentity(new AuthPageViewModeOptions(), out string userName, out ActionResult result);
      Assert.IsFalse(success);
      Assert.IsInstanceOfType(result, typeof(ChallengeResult));
      Assert.IsTrue(((ChallengeResult)result).AuthenticationSchemes.Contains("Negotiate"));
    }

    /// <summary>
    /// A host-registered 'WindowsOnly' policy is still respected (no breaking change).
    /// </summary>
    [TestMethod]
    public void Auto_WithWindowsOnlyPolicy_AvailableAndPolicyEvaluated() {
      OAuth2Controller controller = CreateController(PassThroughMode.Auto, true, true);

      Assert.IsTrue(controller.IsPassThroughAvailable());

      bool success = controller.TryEnsurePassThroughIdentity(new AuthPageViewModeOptions(), out string userName, out ActionResult result);
      Assert.IsFalse(success);
      Assert.IsInstanceOfType(result, typeof(ChallengeResult));
    }

    /// <summary>
    /// An authenticated Windows user passes the check.
    /// </summary>
    [TestMethod]
    public void Auto_AuthenticatedUser_IdentityReturned() {
      OAuth2Controller controller = CreateController(PassThroughMode.Auto, true, false);
      controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(
        new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Name, "DOMAIN\\jdoe") }, "Negotiate")
      );

      bool success = controller.TryEnsurePassThroughIdentity(new AuthPageViewModeOptions(), out string userName, out ActionResult result);
      Assert.IsTrue(success);
      Assert.AreEqual("DOMAIN\\jdoe", userName);
    }

    /// <summary>
    /// 'Off' disables pass-through even if the host supports it, 'On' enables it even without detection.
    /// </summary>
    [TestMethod]
    public void ExplicitModes_OverrideDetection() {
      Assert.IsFalse(CreateController(PassThroughMode.Off, true, true).IsPassThroughAvailable());
      Assert.IsTrue(CreateController(PassThroughMode.On, false, false).IsPassThroughAvailable());

      OAuth2Controller onWithoutHost = CreateController(PassThroughMode.On, false, false);
      bool success = onWithoutHost.TryEnsurePassThroughIdentity(new AuthPageViewModeOptions(), out string userName, out ActionResult result);
      Assert.IsFalse(success);
      Assert.IsInstanceOfType(result, typeof(ContentResult), "a missing host setup must not throw");
    }

    /// <summary>
    /// Creates a controller with a request context, whose services reflect the given host setup.
    /// </summary>
    private static OAuth2Controller CreateController(PassThroughMode mode, bool registerNegotiate, bool registerWindowsOnlyPolicy) {
      ServiceCollection services = new ServiceCollection();
      services.AddLogging();

      CheapOAuthOptions options = new CheapOAuthOptions();
      options.EnablePassThrough = mode;
      services.AddSingleton(options);

      services.AddAuthentication((authenticationOptions) => {
        if (registerNegotiate) {
          authenticationOptions.AddScheme("Negotiate", (scheme) => {
            scheme.HandlerType = typeof(NoResultAuthHandler);
          });
        }
      });

      services.AddAuthorization((authorizationOptions) => {
        if (registerWindowsOnlyPolicy) {
          authorizationOptions.AddPolicy("WindowsOnly", (policy) => {
            policy.AddAuthenticationSchemes("Negotiate");
            policy.RequireAuthenticatedUser();
          });
        }
      });

      DefaultHttpContext httpContext = new DefaultHttpContext();
      httpContext.RequestServices = services.BuildServiceProvider();

      OAuth2Controller controller = new OAuth2Controller(
        NullLogger<OAuth2Controller>.Instance, null, new TemplateAuthPageBuilder("T", null, null)
      );
      controller.ControllerContext = new ControllerContext();
      controller.ControllerContext.HttpContext = httpContext;
      return controller;
    }

    /// <summary>
    /// Simulates a Windows authentication handler for an anonymous request.
    /// </summary>
    private sealed class NoResultAuthHandler : IAuthenticationHandler {

      /// <summary>
      /// Initializes the handler.
      /// </summary>
      public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context) {
        return Task.CompletedTask;
      }

      /// <summary>
      /// No credentials sent yet.
      /// </summary>
      public Task<AuthenticateResult> AuthenticateAsync() {
        return Task.FromResult(AuthenticateResult.NoResult());
      }

      /// <summary>
      /// Challenges the client.
      /// </summary>
      public Task ChallengeAsync(AuthenticationProperties properties) {
        return Task.CompletedTask;
      }

      /// <summary>
      /// Forbids the access.
      /// </summary>
      public Task ForbidAsync(AuthenticationProperties properties) {
        return Task.CompletedTask;
      }

    }

  }

}
