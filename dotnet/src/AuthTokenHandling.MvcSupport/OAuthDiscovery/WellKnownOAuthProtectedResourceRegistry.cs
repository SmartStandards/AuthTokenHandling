#if !NET46

using Microsoft.AspNetCore.Http;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Internal registration seam for the OAuth Protected Resource Metadata feature.
  /// It is populated exclusively by 'AddWellKnownOAuthProtectedResourceEndpoint(...)'.
  /// </summary>
  internal static class WellKnownOAuthProtectedResourceRegistry {

    private static WellKnownOAuthProtectedResourceOptions _Options = null;
    private static readonly object _OptionsLock = new object();

    /// <summary>
    /// Registers the (already validated) options of the protected-resource discovery feature.
    /// </summary>
    internal static void Register(WellKnownOAuthProtectedResourceOptions options) {
      lock (_OptionsLock) {
        _Options = options;
      }
    }

    /// <summary>
    /// Returns the registered options, or null if the feature was not registered.
    /// </summary>
    internal static WellKnownOAuthProtectedResourceOptions GetOptions() {
      lock (_OptionsLock) {
        return _Options;
      }
    }

    /// <summary>
    /// Builds the 'WWW-Authenticate' Bearer challenge which references the protected-resource metadata URL
    /// resolved for the given incoming request. Returns false if the feature was not registered.
    /// </summary>
    internal static bool TryBuildBearerChallenge(HttpRequest request, out string challenge) {
      WellKnownOAuthProtectedResourceOptions options = GetOptions();
      if (options == null) {
        challenge = null;
        return false;
      }
      string metadataUrl = options.ResolveMetadataUrl(request);
      challenge = "Bearer resource_metadata=\"" + EscapeHttpQuotedString(metadataUrl) + "\"";
      return true;
    }

    private static string EscapeHttpQuotedString(string value) {
      if (value == null) {
        return string.Empty;
      }
      return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

  }

}

#endif
