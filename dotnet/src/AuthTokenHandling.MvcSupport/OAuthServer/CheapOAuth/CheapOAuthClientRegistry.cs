using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Registry of the OAuth clients of the Cheap OAuth Server, filled via RFC 7591 dynamic client registration
  /// (as used by MCP clients). Only public clients (PKCE, no secret) are supported.
  /// Protection of the open registration: a maximum number of registrations, expiry of unused registrations
  /// and an optional list of allowed redirect hosts.
  /// Additionally contains the built-in public client 'swagger-ui' (if enabled).
  /// </summary>
  public sealed class CheapOAuthClientRegistry {

    private const string _PersistenceSectionName = "clients";

    private readonly CheapOAuthOptions _Options;
    private readonly Func<DateTime> _UtcNow;
    private readonly ConcurrentDictionary<string, RegisteredClient> _ClientsById = new ConcurrentDictionary<string, RegisteredClient>(StringComparer.Ordinal);
    private readonly object _RegistrationLock = new object();
    private CheapOAuthStatePersistence _Persistence;

    public CheapOAuthClientRegistry(CheapOAuthOptions options) : this(options, null) {
    }

    /// <summary>
    /// Creates the registry with a custom clock (for tests).
    /// </summary>
    public CheapOAuthClientRegistry(CheapOAuthOptions options, Func<DateTime> utcNow) {
      if (options == null) {
        throw new ArgumentNullException(nameof(options));
      }
      _Options = options;
      if (utcNow == null) {
        _UtcNow = () => DateTime.UtcNow;
      }
      else {
        _UtcNow = utcNow;
      }
    }

    /// <summary>
    /// Restores the persisted registrations and writes every subsequent change into the given persistence.
    /// </summary>
    public void AttachPersistence(CheapOAuthStatePersistence persistence) {
      if (persistence == null) {
        throw new ArgumentNullException(nameof(persistence));
      }
      JObject clients = persistence.Load(_PersistenceSectionName) as JObject;
      if (clients != null) {
        foreach (JProperty client in clients.Properties()) {
          JObject entry = client.Value as JObject;
          if (entry == null) {
            continue;
          }
          _ClientsById[client.Name] = new RegisteredClient(
            entry.Value<string>("name"),
            CheapOAuthStatePersistence.ToStringArray(entry["redirectUris"]),
            CheapOAuthStatePersistence.FromUnixMilliseconds(entry["lastUsed"])
          );
        }
      }
      _Persistence = persistence;
      this.RemoveExpiredRegistrations();
    }

    /// <summary>
    /// Registers a new public client and returns its generated client id.
    /// Throws an 'ArgumentException' for invalid metadata and an 'InvalidOperationException' if the limit is reached.
    /// </summary>
    public string RegisterClient(string clientName, string[] redirectUris) {
      if (redirectUris == null || redirectUris.Length == 0) {
        throw new ArgumentException("At least one redirect URI is required.");
      }
      foreach (string redirectUri in redirectUris) {
        string reason;
        if (!this.IsAcceptableRedirectUri(redirectUri, out reason)) {
          throw new ArgumentException("The redirect URI '" + redirectUri + "' is not allowed (" + reason + ").");
        }
      }
      string name = clientName;
      if (name != null) {
        name = name.Trim();
        if (name.Length > 100) {
          name = name.Substring(0, 100);
        }
      }
      lock (_RegistrationLock) {
        this.RemoveExpiredRegistrations();
        if (_ClientsById.Count >= _Options.MaxClientRegistrations) {
          throw new InvalidOperationException("The maximum number of client registrations is reached.");
        }
        string clientId = "client-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        _ClientsById[clientId] = new RegisteredClient(name, redirectUris, _UtcNow());
        this.Persist();
        return clientId;
      }
    }

    /// <summary>
    /// Returns true if the client is registered (or is the enabled built-in Swagger client).
    /// Using a client refreshes its expiry.
    /// </summary>
    public bool IsKnownClient(string clientId) {
      if (string.IsNullOrWhiteSpace(clientId)) {
        return false;
      }
      if (this.IsSwaggerClient(clientId)) {
        return true;
      }
      RegisteredClient client;
      if (!_ClientsById.TryGetValue(clientId, out client)) {
        return false;
      }
      if (this.IsExpired(client)) {
        RegisteredClient removed;
        if (_ClientsById.TryRemove(clientId, out removed)) {
          this.Persist();
        }
        return false;
      }
      this.Touch(clientId, client);
      return true;
    }

    /// <summary>
    /// Returns true if the redirect URI exactly matches one of the registered URIs of the client.
    /// For the built-in Swagger client the path must equal 'SwaggerRedirectPath' and the host must equal the
    /// host of the authorize request (the '{RequestBaseUrl}' placeholder is resolved per request).
    /// </summary>
    public bool IsRegisteredRedirectUri(string clientId, string redirectUri, string requestHost) {
      if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri)) {
        return false;
      }
      if (this.IsSwaggerClient(clientId)) {
        Uri uri;
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out uri)) {
          return false;
        }
        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) {
          return false;
        }
        if (!string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.Query)) {
          return false;
        }
        if (!string.Equals(uri.Host, requestHost, StringComparison.OrdinalIgnoreCase)) {
          return false;
        }
        return uri.AbsolutePath.EndsWith(this.GetSwaggerRedirectPath(), StringComparison.OrdinalIgnoreCase);
      }
      RegisteredClient client;
      if (!_ClientsById.TryGetValue(clientId, out client)) {
        return false;
      }
      foreach (string candidate in client.RedirectUris) {
        if (string.Equals(candidate, redirectUri, StringComparison.Ordinal)) {
          return true;
        }
      }
      return false;
    }

    /// <summary>
    /// Returns the display name of the client (null if unknown or not given at registration).
    /// </summary>
    public string GetClientName(string clientId) {
      if (string.IsNullOrWhiteSpace(clientId)) {
        return null;
      }
      if (this.IsSwaggerClient(clientId)) {
        return "Swagger UI";
      }
      RegisteredClient client;
      if (!_ClientsById.TryGetValue(clientId, out client)) {
        return null;
      }
      return client.Name;
    }

    /// <summary>
    /// The number of dynamic registrations (without the built-in client).
    /// </summary>
    public int RegistrationCount {
      get {
        return _ClientsById.Count;
      }
    }

    private bool IsSwaggerClient(string clientId) {
      if (string.IsNullOrWhiteSpace(_Options.SwaggerRedirectPath)) {
        return false;
      }
      return string.Equals(clientId, CheapOAuthOptions.SwaggerClientId, StringComparison.Ordinal);
    }

    private string GetSwaggerRedirectPath() {
      string path = _Options.SwaggerRedirectPath;
      if (!path.StartsWith("/", StringComparison.Ordinal)) {
        path = "/" + path;
      }
      return path;
    }

    private bool IsExpired(RegisteredClient client) {
      return client.LastUsedUtc.Add(_Options.UnusedClientRegistrationLifetime) <= _UtcNow();
    }

    /// <summary>
    /// Refreshes the last-usage timestamp (persisted at most once per day to limit write load).
    /// </summary>
    private void Touch(string clientId, RegisteredClient client) {
      DateTime now = _UtcNow();
      if (now - client.LastUsedUtc < TimeSpan.FromDays(1)) {
        return;
      }
      _ClientsById[clientId] = new RegisteredClient(client.Name, client.RedirectUris, now);
      this.Persist();
    }

    private void RemoveExpiredRegistrations() {
      bool changed = false;
      foreach (KeyValuePair<string, RegisteredClient> entry in _ClientsById) {
        if (this.IsExpired(entry.Value)) {
          RegisteredClient removed;
          if (_ClientsById.TryRemove(entry.Key, out removed)) {
            changed = true;
          }
        }
      }
      if (changed) {
        this.Persist();
      }
    }

    private void Persist() {
      CheapOAuthStatePersistence persistence = _Persistence;
      if (persistence == null) {
        return;
      }
      persistence.Save(_PersistenceSectionName, () => {
        JObject clients = new JObject();
        foreach (KeyValuePair<string, RegisteredClient> entry in _ClientsById) {
          JObject item = new JObject();
          item["name"] = entry.Value.Name;
          item["redirectUris"] = CheapOAuthStatePersistence.ToJArray(entry.Value.RedirectUris);
          item["lastUsed"] = CheapOAuthStatePersistence.ToUnixMilliseconds(entry.Value.LastUsedUtc);
          clients[entry.Key] = item;
        }
        return clients;
      });
    }

    private bool IsAcceptableRedirectUri(string redirectUri, out string reason) {
      Uri uri;
      if (string.IsNullOrWhiteSpace(redirectUri) || !Uri.TryCreate(redirectUri, UriKind.Absolute, out uri)) {
        reason = "no absolute URI";
        return false;
      }
      if (!string.IsNullOrEmpty(uri.Fragment)) {
        reason = "fragments are not allowed";
        return false;
      }
      if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) {
        reason = "https or http on loopback required";
        return false;
      }
      string[] allowedHosts = _Options.AllowedRedirectHosts;
      if (allowedHosts.Length > 0) {
        bool hostAllowed = false;
        foreach (string allowedHost in allowedHosts) {
          if (string.Equals(allowedHost, uri.Host, StringComparison.OrdinalIgnoreCase)) {
            hostAllowed = true;
          }
        }
        if (!hostAllowed) {
          reason = "host '" + uri.Host + "' is not allowed";
          return false;
        }
      }
      reason = null;
      return true;
    }

    private sealed class RegisteredClient {

      private readonly string _Name;
      private readonly string[] _RedirectUris;
      private readonly DateTime _LastUsedUtc;

      public RegisteredClient(string name, string[] redirectUris, DateTime lastUsedUtc) {
        _Name = name;
        _RedirectUris = redirectUris;
        _LastUsedUtc = lastUsedUtc;
      }

      public string Name {
        get {
          return _Name;
        }
      }

      public string[] RedirectUris {
        get {
          return _RedirectUris;
        }
      }

      public DateTime LastUsedUtc {
        get {
          return _LastUsedUtc;
        }
      }

    }

  }

}
