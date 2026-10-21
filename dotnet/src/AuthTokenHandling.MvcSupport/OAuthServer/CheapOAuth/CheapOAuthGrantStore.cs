using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Store for the short-lived access tokens of the Cheap OAuth Server. Each grant carries (server-side only)
  /// subject, scopes, resource (RFC 8707) and the optional retained secret of the login.
  /// Raw tokens are never stored: the key is the SHA-256 hash of the token.
  /// </summary>
  public sealed class CheapOAuthGrantStore {

    private const string _PersistenceSectionName = "accessGrants";

    private readonly ConcurrentDictionary<string, CheapOAuthGrant> _GrantsByTokenHash;
    private readonly Func<DateTime> _UtcNow;
    private CheapOAuthStatePersistence _Persistence;

    public CheapOAuthGrantStore() : this(null) {
    }

    /// <summary>
    /// Creates a store with a custom clock (for tests).
    /// </summary>
    public CheapOAuthGrantStore(Func<DateTime> utcNow) {
      _GrantsByTokenHash = new ConcurrentDictionary<string, CheapOAuthGrant>(StringComparer.Ordinal);
      if (utcNow == null) {
        _UtcNow = () => DateTime.UtcNow;
      }
      else {
        _UtcNow = utcNow;
      }
    }

    /// <summary>
    /// Restores the persisted (not yet expired) grants and writes every subsequent change into the given persistence.
    /// </summary>
    public void AttachPersistence(CheapOAuthStatePersistence persistence) {
      if (persistence == null) {
        throw new ArgumentNullException(nameof(persistence));
      }
      DateTime now = _UtcNow();
      JArray entries = persistence.Load(_PersistenceSectionName) as JArray;
      if (entries != null) {
        foreach (JToken token in entries) {
          JObject entry = (JObject)token;
          DateTime expiresUtc = CheapOAuthStatePersistence.FromUnixMilliseconds(entry["exp"]);
          if (expiresUtc <= now) {
            continue;
          }
          CheapOAuthGrant grant = new CheapOAuthGrant(
            entry.Value<string>("sub"),
            entry.Value<string>("secret"),
            CheapOAuthStatePersistence.ToStringArray(entry["scopes"]),
            entry.Value<string>("resource"),
            expiresUtc
          );
          _GrantsByTokenHash[entry.Value<string>("hash")] = grant;
        }
      }
      _Persistence = persistence;
    }

    /// <summary>
    /// Issues a new random access token.
    /// </summary>
    public string IssueAccessToken(string subject, string retainedSecret, string[] scopes, string resource, TimeSpan lifetime) {
      if (string.IsNullOrWhiteSpace(subject)) {
        throw new ArgumentException("The subject must not be empty.", nameof(subject));
      }
      if (lifetime <= TimeSpan.Zero) {
        throw new ArgumentException("The lifetime must be positive.", nameof(lifetime));
      }
      this.RemoveExpiredGrants();
      string token = CreateRandomToken();
      string[] grantedScopes = scopes;
      if (grantedScopes == null) {
        grantedScopes = new string[] { };
      }
      _GrantsByTokenHash[HashToken(token)] = new CheapOAuthGrant(subject, retainedSecret, grantedScopes, resource, _UtcNow().Add(lifetime));
      this.Persist();
      return token;
    }

    /// <summary>
    /// Looks up the (not expired) grant of a raw access token (with or without 'Bearer ' prefix).
    /// </summary>
    public bool TryGetGrant(string rawTokenOrAuthHeader, out CheapOAuthGrant grant) {
      grant = null;
      string token = StripBearerPrefix(rawTokenOrAuthHeader);
      if (string.IsNullOrWhiteSpace(token)) {
        return false;
      }
      string hash = HashToken(token);
      CheapOAuthGrant found;
      if (!_GrantsByTokenHash.TryGetValue(hash, out found)) {
        return false;
      }
      if (found.ExpiresUtc <= _UtcNow()) {
        if (_GrantsByTokenHash.TryRemove(hash, out found)) {
          this.Persist();
        }
        return false;
      }
      grant = found;
      return true;
    }

    /// <summary>
    /// Revokes all access tokens of the given subject (e.g. after refresh-token reuse was detected).
    /// </summary>
    public int RevokeAllAccessTokensOfSubject(string subject) {
      int count = 0;
      foreach (KeyValuePair<string, CheapOAuthGrant> entry in _GrantsByTokenHash) {
        if (string.Equals(entry.Value.Subject, subject, StringComparison.OrdinalIgnoreCase)) {
          CheapOAuthGrant removed;
          if (_GrantsByTokenHash.TryRemove(entry.Key, out removed)) {
            count++;
          }
        }
      }
      if (count > 0) {
        this.Persist();
      }
      return count;
    }

    /// <summary>
    /// Removes the 'Bearer ' prefix of an authorization header value (if present).
    /// </summary>
    public static string StripBearerPrefix(string rawTokenOrAuthHeader) {
      if (string.IsNullOrWhiteSpace(rawTokenOrAuthHeader)) {
        return null;
      }
      string value = rawTokenOrAuthHeader.Trim();
      if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
        value = value.Substring(7).Trim();
      }
      return value;
    }

    private void RemoveExpiredGrants() {
      DateTime now = _UtcNow();
      foreach (KeyValuePair<string, CheapOAuthGrant> entry in _GrantsByTokenHash) {
        if (entry.Value.ExpiresUtc <= now) {
          CheapOAuthGrant removed;
          _GrantsByTokenHash.TryRemove(entry.Key, out removed);
        }
      }
    }

    private void Persist() {
      CheapOAuthStatePersistence persistence = _Persistence;
      if (persistence == null) {
        return;
      }
      persistence.Save(_PersistenceSectionName, () => {
        JArray entries = new JArray();
        foreach (KeyValuePair<string, CheapOAuthGrant> entry in _GrantsByTokenHash) {
          JObject item = new JObject();
          item["hash"] = entry.Key;
          item["sub"] = entry.Value.Subject;
          if (entry.Value.RetainedSecret != null) {
            item["secret"] = entry.Value.RetainedSecret;
          }
          item["scopes"] = CheapOAuthStatePersistence.ToJArray(entry.Value.Scopes);
          item["resource"] = entry.Value.Resource;
          item["exp"] = CheapOAuthStatePersistence.ToUnixMilliseconds(entry.Value.ExpiresUtc);
          entries.Add(item);
        }
        return entries;
      });
    }

    internal static string CreateRandomToken() {
      byte[] bytes = RandomNumberGenerator.GetBytes(32);
      return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    internal static string HashToken(string token) {
      byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
      return Convert.ToHexString(hash);
    }

  }

  /// <summary>
  /// A server-side grant which belongs to an access token of the Cheap OAuth Server.
  /// </summary>
  public sealed class CheapOAuthGrant {

    private readonly string _Subject;
    private readonly string _RetainedSecret;
    private readonly string[] _Scopes;
    private readonly string _Resource;
    private readonly DateTime _ExpiresUtc;

    public CheapOAuthGrant(string subject, string retainedSecret, string[] scopes, string resource, DateTime expiresUtc) {
      _Subject = subject;
      _RetainedSecret = retainedSecret;
      _Scopes = scopes;
      _Resource = resource;
      _ExpiresUtc = expiresUtc;
    }

    public string Subject {
      get {
        return _Subject;
      }
    }

    /// <summary>
    /// The secret retained by the credential source (see 'CheapOAuthLoginResult.Valid'); never exposed via introspection.
    /// </summary>
    public string RetainedSecret {
      get {
        return _RetainedSecret;
      }
    }

    public string[] Scopes {
      get {
        return _Scopes;
      }
    }

    /// <summary>
    /// The resource indicator (RFC 8707) of the authorize request (null if none was given).
    /// </summary>
    public string Resource {
      get {
        return _Resource;
      }
    }

    public DateTime ExpiresUtc {
      get {
        return _ExpiresUtc;
      }
    }

  }

}
