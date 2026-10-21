#if !NET46

using Microsoft.AspNetCore.Http;
using System;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Configures OAuth Protected Resource Metadata according to RFC 9728.
  /// </summary>
  public sealed class WellKnownOAuthProtectedResourceOptions {

    private string _Resource;
    private string[] _AuthorizationServers;
    private string[] _ScopesSupported;
    private string _MetadataUrl;
    private bool _EmitChallengeForAllAdapters;
    private bool _ApplyApiPermissionPrefixToScopesSupported;

    public WellKnownOAuthProtectedResourceOptions() {
      _Resource = null;
      _AuthorizationServers = new string[] { };
      _ScopesSupported = new string[] { };
      _MetadataUrl = null;
      _EmitChallengeForAllAdapters = false;
    }

    /// <summary>
    /// OPT-IN (default false): if true, the configured API permission prefix (e.g. 'API:') is applied to the
    /// published 'scopes_supported' (unless already present) at the time of the request (symmetry rule).
    /// Default false keeps the released behavior (published literally).
    /// </summary>
    public bool ApplyApiPermissionPrefixToScopesSupported {
      get {
        return _ApplyApiPermissionPrefixToScopesSupported;
      }
      set {
        _ApplyApiPermissionPrefixToScopesSupported = value;
      }
    }

    /// <summary>
    /// OPT-IN (default false): if true, the 401 challenge
    /// wired up for all other adapters (UJMW hook, WCF inspector) by configuring the
    /// 'AccessTokenValidator.ConfigureChallengeHeaders' builder (a builder configured explicitly by the host
    /// is never overwritten). Default false keeps the released behavior: only 'EvaluateBearerTokenAttribute' emits it.
    /// </summary>
    public bool EmitChallengeForAllAdapters {
      get {
        return _EmitChallengeForAllAdapters;
      }
      set {
        _EmitChallengeForAllAdapters = value;
      }
    }

    /// <summary>
    /// Gets or sets the protected resource identifier URL.
    /// If the value does not start with 'http://' or 'https://', it will be qualified dynamically
    /// using the scheme, host and path base of the incoming request. If empty, the request base URL is used.
    /// </summary>
    public string Resource {
      get {
        return _Resource;
      }
      set {
        _Resource = value;
      }
    }

    /// <summary>
    /// Gets or sets the authorization server issuer URLs that can issue tokens for this resource.
    /// Relative entries will be qualified dynamically using the incoming request. If empty, the request base URL is used
    /// (which matches a host that also exposes the OAuth server controller).
    /// </summary>
    public string[] AuthorizationServers {
      get {
        return _AuthorizationServers;
      }
      set {
        if (value == null) {
          _AuthorizationServers = new string[] { };
        }
        else {
          _AuthorizationServers = value;
        }
      }
    }

    /// <summary>
    /// Gets or sets the scopes supported by this protected resource.
    /// </summary>
    public string[] ScopesSupported {
      get {
        return _ScopesSupported;
      }
      set {
        if (value == null) {
          _ScopesSupported = new string[] { };
        }
        else {
          _ScopesSupported = value;
        }
      }
    }

    /// <summary>
    /// Gets or sets the public metadata URL referenced from WWW-Authenticate challenges.
    /// Relative values will be qualified dynamically using the incoming request.
    /// If empty, '{resource}/.well-known/oauth-protected-resource' is used.
    /// </summary>
    public string MetadataUrl {
      get {
        return _MetadataUrl;
      }
      set {
        _MetadataUrl = value;
      }
    }

    /// <summary>
    /// Validates the configured metadata fields.
    /// </summary>
    public void Validate() {
      if (_AuthorizationServers != null) {
        foreach (string authorizationServer in _AuthorizationServers) {
          if (string.IsNullOrWhiteSpace(authorizationServer)) {
            throw new ArgumentException($"'{nameof(AuthorizationServers)}' must not contain empty entries!");
          }
        }
      }
    }

    /// <summary>
    /// Resolves the absolute protected resource identifier for the given incoming request.
    /// </summary>
    internal string ResolveResource(HttpRequest request) {
      return this.ResolveResource(request, null);
    }

    /// <summary>
    /// Resolves the absolute protected resource identifier for the given incoming request.
    /// If a sub resource path is given (because '.well-known' was addressed below or with a suffix
    /// below the API root) and the configured 'Resource' is not an absolute URL, the path is appended,
    /// so that the returned 'resource' matches the URL which was used to build the metadata URL (RFC 9728).
    /// </summary>
    internal string ResolveResource(HttpRequest request, string subResourcePath) {
      string resource;
      if (string.IsNullOrWhiteSpace(_Resource)) {
        resource = TrimTrailingSlash(GetRequestBaseUrl(request));
      }
      else {
        if (IsAbsoluteHttpUrl(_Resource)) {
          return TrimTrailingSlash(_Resource);
        }
        resource = TrimTrailingSlash(QualifyUrl(_Resource, request));
      }
      if (string.IsNullOrWhiteSpace(subResourcePath)) {
        return resource;
      }
      string trimmedSubResourcePath = subResourcePath.Trim('/');
      if (trimmedSubResourcePath.Length == 0) {
        return resource;
      }
      return resource + "/" + trimmedSubResourcePath;
    }

    /// <summary>
    /// Resolves the absolute authorization server issuer URLs for the given incoming request.
    /// </summary>
    internal string[] ResolveAuthorizationServers(HttpRequest request) {
      if (_AuthorizationServers == null || _AuthorizationServers.Length == 0) {
        return new string[] { TrimTrailingSlash(GetRequestBaseUrl(request)) };
      }
      string[] resolved = new string[_AuthorizationServers.Length];
      for (int i = 0; i < _AuthorizationServers.Length; i++) {
        resolved[i] = TrimTrailingSlash(QualifyUrl(_AuthorizationServers[i], request));
      }
      return resolved;
    }

    /// <summary>
    /// Resolves the absolute metadata URL used in Bearer challenges for the given incoming request.
    /// </summary>
    internal string ResolveMetadataUrl(HttpRequest request) {
      if (!string.IsNullOrWhiteSpace(_MetadataUrl)) {
        return QualifyUrl(_MetadataUrl, request);
      }
      return this.ResolveResource(request) + "/.well-known/oauth-protected-resource";
    }

    /// <summary>
    /// Builds the metadata URL WITHOUT a request: relative parts are prefixed with the configured
    /// 'AccessTokenManager.PublicBaseUrl' or (if not configured) with the literal placeholder '{RequestBaseUrl}',
    /// which MUST be replaced by every HTTP adapter with the base URL of its own request (official convention).
    /// </summary>
    internal string BuildMetadataUrlTemplate() {
      string baseUrl = AccessTokenManager.PublicBaseUrl;
      if (string.IsNullOrWhiteSpace(baseUrl)) {
        baseUrl = AccessTokenManager.RequestBaseUrlPlaceholder;
      }
      else {
        baseUrl = TrimTrailingSlash(baseUrl);
      }
      if (!string.IsNullOrWhiteSpace(_MetadataUrl)) {
        return QualifyUrlTemplate(_MetadataUrl, baseUrl);
      }
      string resource;
      if (string.IsNullOrWhiteSpace(_Resource)) {
        resource = baseUrl;
      }
      else {
        resource = TrimTrailingSlash(QualifyUrlTemplate(_Resource, baseUrl));
      }
      return resource + "/.well-known/oauth-protected-resource";
    }

    private static string QualifyUrlTemplate(string url, string baseUrl) {
      if (IsAbsoluteHttpUrl(url) || url.StartsWith(AccessTokenManager.RequestBaseUrlPlaceholder, StringComparison.Ordinal)) {
        return url;
      }
      string relativePart = url.Trim();
      if (relativePart == "/") {
        return baseUrl;
      }
      if (!relativePart.StartsWith("/")) {
        relativePart = "/" + relativePart;
      }
      return baseUrl + relativePart;
    }

    /// <summary>
    /// Returns the given URL unchanged if it is already absolute (starts with 'http://' or 'https://'),
    /// otherwise it will be prefixed with the base URL of the incoming request.
    /// </summary>
    private static string QualifyUrl(string url, HttpRequest request) {
      if (IsAbsoluteHttpUrl(url)) {
        return url;
      }
      string requestBaseUrl = TrimTrailingSlash(GetRequestBaseUrl(request));
      string relativePart = url.Trim();
      if (relativePart == "/") {
        return requestBaseUrl;
      }
      if (!relativePart.StartsWith("/")) {
        relativePart = "/" + relativePart;
      }
      return requestBaseUrl + relativePart;
    }

    private static bool IsAbsoluteHttpUrl(string url) {
      if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) {
        return true;
      }
      if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
        return true;
      }
      return false;
    }

    /// <summary>
    /// Builds '{scheme}://{host}{pathBase}' from the incoming request.
    /// </summary>
    private static string GetRequestBaseUrl(HttpRequest request) {
      if (request == null) {
        throw new ArgumentNullException(nameof(request));
      }
      return request.Scheme + "://" + request.Host.ToUriComponent() + request.PathBase.ToUriComponent();
    }

    private static string TrimTrailingSlash(string value) {
      if (string.IsNullOrWhiteSpace(value)) {
        return value;
      }
      return value.TrimEnd('/');
    }

  }

}

#endif
