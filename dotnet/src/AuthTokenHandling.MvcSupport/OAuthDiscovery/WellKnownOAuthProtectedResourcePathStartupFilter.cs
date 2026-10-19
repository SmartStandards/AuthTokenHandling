#if !NET46

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Makes the protected-resource metadata endpoint reachable on any path level
  /// (for example '/foo/bar/.well-known/oauth-protected-resource'), because ASP.NET Core routing
  /// does not support catch-all parameters in front of a fixed route segment.
  /// The prefix is moved into 'HttpContext.Items' and the request path is normalized to the root route.
  /// </summary>
  internal sealed class WellKnownOAuthProtectedResourcePathStartupFilter : IStartupFilter {

    internal const string PathMarker = "/.well-known/oauth-protected-resource";
    internal const string PrefixItemKey = "AccessTokenHandling.WellKnownOAuthProtectedResource.Prefix";

    /// <summary>
    /// Places the path normalization in front of the host pipeline (before routing).
    /// </summary>
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) {
      return (app) => {
        app.Use(
          (context, nextMiddleware) => {
            NormalizePath(context);
            return nextMiddleware();
          }
        );
        next(app);
      };
    }

    /// <summary>
    /// Rewrites '{prefix}/.well-known/oauth-protected-resource[/suffix]' to
    /// '/.well-known/oauth-protected-resource[/suffix]' and stores the prefix.
    /// </summary>
    private static void NormalizePath(HttpContext context) {
      string path = context.Request.Path.Value;
      if (string.IsNullOrEmpty(path)) {
        return;
      }

      int markerIndex = path.IndexOf(PathMarker, StringComparison.OrdinalIgnoreCase);
      if (markerIndex <= 0) {
        return;
      }

      string remainingPath = path.Substring(markerIndex);
      bool isExactMarker = remainingPath.Length == PathMarker.Length;
      bool isMarkerWithSuffix = remainingPath.Length > PathMarker.Length && remainingPath[PathMarker.Length] == '/';
      if (!isExactMarker && !isMarkerWithSuffix) {
        return;
      }

      context.Items[PrefixItemKey] = path.Substring(0, markerIndex);
      context.Request.Path = new PathString(remainingPath);
    }

  }

}

#endif
