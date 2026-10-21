namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// The capabilities of an authorization server, which are published as RFC 8414 authorization server metadata
  /// (provided by 'IOAuthService.GetAuthorizationServerCapabilities'). The endpoint URLs are not part of it,
  /// because they are owned by the controller.
  /// </summary>
  public class AuthorizationServerCapabilities {

    private string[] _ResponseTypesSupported = new string[] { "code" };
    private string[] _GrantTypesSupported = new string[] { "authorization_code" };
    private string[] _CodeChallengeMethodsSupported = new string[] { "S256" };
    private string[] _TokenEndpointAuthMethodsSupported = new string[] { "client_secret_post" };
    private string[] _ScopesSupported = new string[] { };
    private bool _SupportsDynamicClientRegistration = false;

    /// <summary>
    /// 'response_types_supported' (default: 'code').
    /// </summary>
    public string[] ResponseTypesSupported {
      get {
        return _ResponseTypesSupported;
      }
      set {
        _ResponseTypesSupported = value;
      }
    }

    /// <summary>
    /// 'grant_types_supported' (default: 'authorization_code').
    /// </summary>
    public string[] GrantTypesSupported {
      get {
        return _GrantTypesSupported;
      }
      set {
        _GrantTypesSupported = value;
      }
    }

    /// <summary>
    /// 'code_challenge_methods_supported' (default: 'S256' - the OAuth2Controller always supports PKCE S256).
    /// </summary>
    public string[] CodeChallengeMethodsSupported {
      get {
        return _CodeChallengeMethodsSupported;
      }
      set {
        _CodeChallengeMethodsSupported = value;
      }
    }

    /// <summary>
    /// 'token_endpoint_auth_methods_supported' (default: 'client_secret_post'; 'none' for public clients).
    /// </summary>
    public string[] TokenEndpointAuthMethodsSupported {
      get {
        return _TokenEndpointAuthMethodsSupported;
      }
      set {
        _TokenEndpointAuthMethodsSupported = value;
      }
    }

    /// <summary>
    /// 'scopes_supported' - exactly as they should be published (already prefixed, if a prefix is used).
    /// Not published if empty.
    /// </summary>
    public string[] ScopesSupported {
      get {
        return _ScopesSupported;
      }
      set {
        _ScopesSupported = value;
      }
    }

    /// <summary>
    /// True, if 'TryRegisterClient' (RFC 7591) is supported - then the 'registration_endpoint' is published.
    /// </summary>
    public bool SupportsDynamicClientRegistration {
      get {
        return _SupportsDynamicClientRegistration;
      }
      set {
        _SupportsDynamicClientRegistration = value;
      }
    }

  }

}
