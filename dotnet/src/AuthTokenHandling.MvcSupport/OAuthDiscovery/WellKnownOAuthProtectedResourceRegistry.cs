#if !NET46

using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;

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

    /// <summary>
    /// Challenge header builder ('AccessTokenValidator.ConfigureChallengeHeaders') which is wired up automatically by
    /// 'AddWellKnownOAuthProtectedResourceEndpoint(...)'. It emits 'WWW-Authenticate: Bearer resource_metadata="..."'
    /// (plus 'scope="..."' when scopes are required) for 401 rejections. The value contains the placeholder
    /// '{RequestBaseUrl}' (unless a public base url is configured), which MUST be replaced by the HTTP adapter.
    /// </summary>
    internal static KeyValuePair<string, string>[] BuildChallengeHeaders(int statusCode, string[] requiredScopes) {
      WellKnownOAuthProtectedResourceOptions options = GetOptions();
      if (options == null || statusCode != 401) {
        return new KeyValuePair<string, string>[] { };
      }
      string challenge = "Bearer resource_metadata=\"" + EscapeHttpQuotedString(options.BuildMetadataUrlTemplate()) + "\"";
      string scopeParameter = BuildScopeParameter(requiredScopes);
      if (scopeParameter.Length > 0) {
        //symmetry rule: the required scopes are advertised exactly as they are checked (prefixed)
        challenge = challenge + ", scope=\"" + EscapeHttpQuotedString(scopeParameter) + "\"";
      }
      return new KeyValuePair<string, string>[] { new KeyValuePair<string, string>("WWW-Authenticate", challenge) };
    }

    /// <summary>
    /// Returns the blank-separated required scopes (already prefixed by the validator; "" if there are none).
    /// </summary>
    internal static string BuildScopeParameter(string[] requiredScopes) {
      List<string> scopes = new List<string>();
      if (requiredScopes == null) {
        return string.Empty;
      }
      foreach (string scope in requiredScopes) {
        if (string.IsNullOrWhiteSpace(scope)) {
          continue;
        }
        string effectiveScope = scope.Trim();
        if (!scopes.Contains(effectiveScope, StringComparer.OrdinalIgnoreCase)) {
          scopes.Add(effectiveScope);
        }
      }
      return string.Join(" ", scopes);
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
