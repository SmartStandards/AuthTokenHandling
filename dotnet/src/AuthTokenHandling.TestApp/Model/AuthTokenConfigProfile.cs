using Security.AccessTokenHandling;
using System.Collections.Generic;

namespace AuthTokenHandling.TestApp.Model {

  /// <summary>
  /// A named, per-user persisted 'AuthTokenConfig' together with the additional (test-client only)
  /// settings, which are required to play through OAuth flows.
  /// </summary>
  public sealed class AuthTokenConfigProfile {

    private string _Name = "New Profile";
    private AuthTokenConfig _Config = new AuthTokenConfig();
    private OAuthFlowSettings _OAuth = new OAuthFlowSettings();

    /// <summary>
    /// Unique name of the profile (used as key).
    /// </summary>
    public string Name {
      get {
        return _Name;
      }
      set {
        _Name = value;
      }
    }

    /// <summary>
    /// The complete 'AuthTokenConfig' structure (exactly the shape, which is consumed by the factories).
    /// </summary>
    public AuthTokenConfig Config {
      get {
        return _Config;
      }
      set {
        _Config = value;
      }
    }

    /// <summary>
    /// Additional settings for the OAuth flows (provider selection, redirect uri, scopes, ...).
    /// </summary>
    public OAuthFlowSettings OAuth {
      get {
        return _OAuth;
      }
      set {
        _OAuth = value;
      }
    }

  }

  /// <summary>
  /// Settings, which are not part of the 'AuthTokenConfig', but required to execute OAuth flows
  /// via an 'IOAuthOperationsProvider'.
  /// </summary>
  public sealed class OAuthFlowSettings {

    private string _ProviderType = "generic";
    private Dictionary<string, string> _ProviderConfiguration = new Dictionary<string, string>();
    private string _RedirectUri = "http://127.0.0.1:20000";
    private string _Scopes = "openid";
    private string _GrantType = "code";
    private string _State = string.Empty;
    private bool _RequestRefreshToken = false;
    private bool _RequestIdToken = false;
    private bool _TryKeepBrowserInvisible = false;

    /// <summary>
    /// One of: generic, microsoft, google, github, facebook, apple.
    /// </summary>
    public string ProviderType {
      get {
        return _ProviderType;
      }
      set {
        _ProviderType = value;
      }
    }

    /// <summary>
    /// Additional raw configuration values, which are passed to 'IOAuthOperationsProvider.SetConfigurationValue'
    /// (they override the values derived from the 'AuthTokenConfig').
    /// </summary>
    public Dictionary<string, string> ProviderConfiguration {
      get {
        return _ProviderConfiguration;
      }
      set {
        _ProviderConfiguration = value;
      }
    }

    public string RedirectUri {
      get {
        return _RedirectUri;
      }
      set {
        _RedirectUri = value;
      }
    }

    /// <summary>
    /// Space separated scopes to request.
    /// </summary>
    public string Scopes {
      get {
        return _Scopes;
      }
      set {
        _Scopes = value;
      }
    }

    /// <summary>
    /// 'code' or 'implicit' (only relevant for the interactive flow).
    /// </summary>
    public string GrantType {
      get {
        return _GrantType;
      }
      set {
        _GrantType = value;
      }
    }

    /// <summary>
    /// Optional fixed 'state' (a random one is generated when empty).
    /// </summary>
    public string State {
      get {
        return _State;
      }
      set {
        _State = value;
      }
    }

    public bool RequestRefreshToken {
      get {
        return _RequestRefreshToken;
      }
      set {
        _RequestRefreshToken = value;
      }
    }

    public bool RequestIdToken {
      get {
        return _RequestIdToken;
      }
      set {
        _RequestIdToken = value;
      }
    }

    public bool TryKeepBrowserInvisible {
      get {
        return _TryKeepBrowserInvisible;
      }
      set {
        _TryKeepBrowserInvisible = value;
      }
    }

  }

}
