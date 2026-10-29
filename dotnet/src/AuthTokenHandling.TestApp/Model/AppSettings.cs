namespace AuthTokenHandling.TestApp.Model {

  /// <summary>
  /// Root of the per-user settings file.
  /// </summary>
  public sealed class AppSettings {

    private AuthTokenConfigProfile[] _Profiles = new AuthTokenConfigProfile[0];
    private string _CurrentProfileName = string.Empty;
    private TokenSet _LastTokens = new TokenSet();

    public AuthTokenConfigProfile[] Profiles {
      get {
        return _Profiles;
      }
      set {
        _Profiles = value;
      }
    }

    public string CurrentProfileName {
      get {
        return _CurrentProfileName;
      }
      set {
        _CurrentProfileName = value;
      }
    }

    /// <summary>
    /// The most recently obtained tokens (restored on startup for convenience).
    /// </summary>
    public TokenSet LastTokens {
      get {
        return _LastTokens;
      }
      set {
        _LastTokens = value;
      }
    }

  }

  /// <summary>
  /// The token values shown in the token panel of the UI.
  /// </summary>
  public sealed class TokenSet {

    private string _AccessToken = string.Empty;
    private string _RefreshToken = string.Empty;
    private string _IdToken = string.Empty;

    public string AccessToken {
      get {
        return _AccessToken;
      }
      set {
        _AccessToken = value;
      }
    }

    public string RefreshToken {
      get {
        return _RefreshToken;
      }
      set {
        _RefreshToken = value;
      }
    }

    public string IdToken {
      get {
        return _IdToken;
      }
      set {
        _IdToken = value;
      }
    }

  }

}
