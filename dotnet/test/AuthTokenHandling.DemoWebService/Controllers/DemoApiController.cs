using Microsoft.AspNetCore.Mvc;
using Security.AccessTokenHandling;
using System;

namespace Security.Controllers {

  /// <summary>
  /// A tiny protected API, which demonstrates the token validation against the Cheap OAuth Server.
  /// The API group 'DemoApi' requires the scope 'demo' (see Startup: 'AccessTokenManager.RequireScope').
  /// </summary>
  [ApiController]
  [Route("api/demo")]
  [ApiExplorerSettings(GroupName = Program.DemoApiGroupName)]
  public class DemoApiController : ControllerBase {

    /// <summary>
    /// Returns a greeting - only accessible with a valid access token (scope 'demo').
    /// </summary>
    [EvaluateBearerToken]
    [HttpGet("hello")]
    [Produces("application/json")]
    public string Hello() {
      return "Hello! Your access token was accepted at " + DateTime.UtcNow.ToString("u") + ".";
    }

  }

}
