using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    // https://www.rfc-editor.org/rfc/rfc7662

    [HttpPost(), Produces("application/json")]
    [Route("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    public Dictionary<string, object> Introspect([FromForm] IFormCollection value) {
      try {

        string token = null;
        //string tokenTypeHint = null;

        if (value.TryGetValue("token", out StringValues tokenValue)) {
          token = tokenValue.ToString();
        }

        //OPTIONAL!!!
        //if (value.TryGetValue("token_type_hint", out StringValues tokenTypeHintValue)) {
        //  tokenTypeHint = tokenTypeHintValue.ToString();
        //}

        _AuthService.IntrospectAccessToken(token, out bool active, out Dictionary<String, object> dict);
        dict["active"] = active;

        return dict;
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        return new Dictionary<string, object>() {
          { "active", false },
          { "inactive_reason", "Processing Error (Introspection Endpoint)" },
        };
      }
    }

  }

}
