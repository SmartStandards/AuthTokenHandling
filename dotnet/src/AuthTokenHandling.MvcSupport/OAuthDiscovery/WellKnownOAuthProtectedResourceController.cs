#if !NET46

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace Security.AccessTokenHandling {

  [ApiController]
  [ApiExplorerSettings(GroupName = ".well-known")]
  internal sealed class WellKnownOAuthProtectedResourceController : ControllerBase {

    /// <summary>
    /// Returns OAuth Protected Resource Metadata according to RFC 9728.
    /// Relative URLs from the configuration are qualified on-demand using the incoming request.
    /// The endpoint answers on any path level ('{prefix}/.well-known/oauth-protected-resource')
    /// as well as with an RFC 9728 path suffix ('/.well-known/oauth-protected-resource/{resourcePath}').
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    [Route(".well-known/oauth-protected-resource")]
    [Route(".well-known/oauth-protected-resource/{*resourcePath}")]
    public ContentResult GetMetadata() {

      WellKnownOAuthProtectedResourceOptions options = WellKnownOAuthProtectedResourceRegistry.GetOptions();
      if (options == null) {
        return new ContentResult() {
          StatusCode = 500,
          Content = "Protected resource metadata is not configured!"
        };
      }

      string subResourcePath = this.GetSubResourcePath();

      JObject document = new JObject();
      document["resource"] = options.ResolveResource(this.Request, subResourcePath);
      document["authorization_servers"] = JArray.FromObject(options.ResolveAuthorizationServers(this.Request));

      if (options.ScopesSupported != null && options.ScopesSupported.Length > 0) {
        document["scopes_supported"] = JArray.FromObject(options.ScopesSupported);
      }

      string json = document.ToString(Formatting.None);
      return new ContentResult() {
        StatusCode = 200,
        ContentType = "application/json; charset=utf-8",
        Content = json
      };
    }

    /// <summary>
    /// Combines the path prefix (in front of '.well-known', see 'WellKnownOAuthProtectedResourcePathStartupFilter')
    /// and the RFC 9728 path suffix (behind 'oauth-protected-resource') into one sub resource path.
    /// </summary>
    private string GetSubResourcePath() {
      string prefix = string.Empty;
      object prefixUntyped;
      if (this.HttpContext.Items.TryGetValue(WellKnownOAuthProtectedResourcePathStartupFilter.PrefixItemKey, out prefixUntyped)) {
        prefix = Convert.ToString(prefixUntyped).Trim('/');
      }

      string suffix = string.Empty;
      object suffixUntyped;
      if (this.RouteData.Values.TryGetValue("resourcePath", out suffixUntyped)) {
        if (suffixUntyped != null) {
          suffix = Convert.ToString(suffixUntyped).Trim('/');
        }
      }

      if (prefix.Length == 0) {
        return suffix;
      }
      if (suffix.Length == 0) {
        return prefix;
      }
      return prefix + "/" + suffix;
    }

  }

}

#endif
