using System;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Strategy to persist the tokens of a token source (access token, refresh token, id token)
  /// beyond the lifetime of the current process. Used by the AccessTokenManager only when
  /// persistence was explicitly enabled (opt-in) via 'AccessTokenManager.ConfigureTokenSupply(...)'.
  /// </summary>
  public interface ITokenPersistenceProvider {

    /// <summary>
    /// Loads the persisted tokens of a token source.
    /// </summary>
    /// <param name="tokenSourceId">The resolved token source id.</param>
    /// <param name="userScope">true: per application runtime user, false: machine wide.</param>
    /// <param name="customScope">An additional isolation scope (empty string if not used).</param>
    /// <param name="tokens">The loaded tokens (never null when true is returned).</param>
    /// <returns>true, if tokens were found and could be read.</returns>
    bool TryLoadTokens(string tokenSourceId, bool userScope, string customScope, out PersistedTokenSet tokens);

    /// <summary>
    /// Saves (replaces) the persisted tokens of a token source.
    /// </summary>
    /// <param name="tokenSourceId">The resolved token source id.</param>
    /// <param name="userScope">true: per application runtime user, false: machine wide.</param>
    /// <param name="customScope">An additional isolation scope (empty string if not used).</param>
    /// <param name="tokens">The tokens to persist.</param>
    void SaveTokens(string tokenSourceId, bool userScope, string customScope, PersistedTokenSet tokens);

    /// <summary>
    /// Deletes the persisted tokens of a token source (if existing).
    /// </summary>
    /// <param name="tokenSourceId">The resolved token source id.</param>
    /// <param name="userScope">true: per application runtime user, false: machine wide.</param>
    /// <param name="customScope">An additional isolation scope (empty string if not used).</param>
    void DeleteTokens(string tokenSourceId, bool userScope, string customScope);

  }

  /// <summary>
  /// The set of tokens which is persisted for one token source.
  /// Empty strings represent tokens which are not present.
  /// </summary>
  public class PersistedTokenSet {

    private string _AccessToken = string.Empty;
    private string _RefreshToken = string.Empty;
    private string _IdToken = string.Empty;
    private DateTime _AccessTokenExpiresUtc = DateTime.MaxValue;

    public string AccessToken {
      get {
        return _AccessToken;
      }
      set {
        _AccessToken = NormalizeToken(value);
      }
    }

    public string RefreshToken {
      get {
        return _RefreshToken;
      }
      set {
        _RefreshToken = NormalizeToken(value);
      }
    }

    public string IdToken {
      get {
        return _IdToken;
      }
      set {
        _IdToken = NormalizeToken(value);
      }
    }

    /// <summary>
    /// Expiry of the access token in UTC (DateTime.MaxValue if unknown).
    /// </summary>
    public DateTime AccessTokenExpiresUtc {
      get {
        return _AccessTokenExpiresUtc;
      }
      set {
        _AccessTokenExpiresUtc = value;
      }
    }

    /// <summary>
    /// Converts null into an empty string.
    /// </summary>
    private static string NormalizeToken(string value) {
      if (value == null) {
        return string.Empty;
      }
      return value;
    }

  }

}
