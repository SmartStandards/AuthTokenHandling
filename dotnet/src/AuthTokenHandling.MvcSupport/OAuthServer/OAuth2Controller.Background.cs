using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    /// <summary>
    /// Serves the (optionally CI-color transformed) background image of the OAuth pages.
    /// The transformed images are cached in memory by the 'TemplateAuthPageBuilder'.
    /// </summary>
    /// <param name="ciColor">Optional CI color as hex value without '#' (only colors configured on a builder are served).</param>
    [Route("background.png")]
    [Route("sso/background.png")]
    [AllowAnonymous]
    [HttpGet(), Produces("image/png")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public ActionResult GetBackgroundImage([FromQuery(Name = "ci")] string ciColor = null) {

      byte[] png = TemplateAuthPageBuilder.GetBackgroundImagePng(ciColor);

      if (png == null) {
        return this.NotFound();
      }

      this.Response.Headers["Cache-Control"] = "public, max-age=86400";

      return this.File(png, "image/png");
    }

  }

}
