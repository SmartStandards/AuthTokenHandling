using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Options of the 'Cheap OAuth Server' (see 'CheapOAuthSetupExtensions.AddCheapOAuthServer').
  /// The Cheap OAuth Server is deliberately the small solution that works out of the box:
  /// exactly ONE credential source (a lambda, a fixed account list or a configuration section).
  /// </summary>
  public sealed class CheapOAuthOptions {

    /// <summary>
    /// The client id of the built-in public client for the Swagger UI.
    /// </summary>
    public const string SwaggerClientId = "swagger-ui";

    private Func<string, string, CheapOAuthLoginResult> _ValidateLogin;
    private string _TokenSourceId;
    private string _PersistToDir;
    private string _PersistencePassphrase;
    private string _LoginPageTitle;
    private string _LoginPageBackgroundCiColor;
    private string _LoginPageCustomBackgroundImageUrl;
    private TimeSpan _AccessTokenLifetime;
    private TimeSpan _RefreshTokenLifetime;
    private int _MaxClientRegistrations;
    private TimeSpan _UnusedClientRegistrationLifetime;
    private string[] _AllowedRedirectHosts;
    private string _SwaggerRedirectPath;
    private string[] _DefaultScopes;
    private string[] _ScopesSupported;
    private bool _RegisterProtectedResourceMetadata;
    private PassThroughMode _EnablePassThrough;

    public CheapOAuthOptions() {
      _ValidateLogin = null;
      _TokenSourceId = AccessTokenManager.DefaultTokenSourceId;
      _PersistToDir = null;
      _PersistencePassphrase = null;
      _LoginPageTitle = "Login";
      _AccessTokenLifetime = TimeSpan.FromMinutes(15);
      _RefreshTokenLifetime = TimeSpan.FromDays(30);
      _MaxClientRegistrations = 1000;
      _UnusedClientRegistrationLifetime = TimeSpan.FromDays(30);
      _AllowedRedirectHosts = new string[] { };
      _SwaggerRedirectPath = "/docs/oauth2-redirect.html";
      _DefaultScopes = new string[] { };
      _ScopesSupported = new string[] { };
      _RegisterProtectedResourceMetadata = true;
      _EnablePassThrough = PassThroughMode.Auto;
    }

    #region " Credential Source "

    /// <summary>
    /// The one and only credential source: validates user name and password (e.g. against a backend).
    /// Setting this replaces any account list configured before.
    /// </summary>
    public Func<string, string, CheapOAuthLoginResult> ValidateLogin {
      get {
        return _ValidateLogin;
      }
      set {
        _ValidateLogin = value;
      }
    }

    /// <summary>
    /// Uses a fixed account list as credential source (replaces any credential source configured before).
    /// </summary>
    public void UseFixedAccounts(params (string userName, string password, string[] scopes)[] accounts) {
      if (accounts == null) {
        throw new ArgumentNullException(nameof(accounts));
      }
      Dictionary<string, FixedAccount> accountsByName = new Dictionary<string, FixedAccount>(StringComparer.OrdinalIgnoreCase);
      foreach ((string userName, string password, string[] scopes) account in accounts) {
        if (string.IsNullOrWhiteSpace(account.userName)) {
          throw new ArgumentException("The user name of an account must not be empty.", nameof(accounts));
        }
        if (string.IsNullOrEmpty(account.password)) {
          throw new ArgumentException("The password of account '" + account.userName + "' must not be empty.", nameof(accounts));
        }
        string[] scopes = account.scopes;
        if (scopes == null) {
          scopes = new string[] { };
        }
        accountsByName[account.userName] = new FixedAccount(HashSecret(account.password), scopes);
      }
      _ValidateLogin = (userName, password) => {
        FixedAccount found;
        if (!accountsByName.TryGetValue(userName, out found)) {
          return CheapOAuthLoginResult.Invalid();
        }
        if (!CryptographicOperations.FixedTimeEquals(found.PasswordHash, HashSecret(password))) {
          return CheapOAuthLoginResult.Invalid();
        }
        return CheapOAuthLoginResult.Valid(found.Scopes);
      };
    }

    /// <summary>
    /// Uses the accounts of a configuration section as credential source (replaces any credential source configured before).
    /// Expected shape: an array of objects with 'UserName', 'Password' and (optional) 'Scopes' (string array).
    /// </summary>
    public void UseAccountsFromConfiguration(IConfiguration accountsSection) {
      if (accountsSection == null) {
        throw new ArgumentNullException(nameof(accountsSection));
      }
      List<(string userName, string password, string[] scopes)> accounts = new List<(string userName, string password, string[] scopes)>();
      foreach (IConfigurationSection accountSection in accountsSection.GetChildren()) {
        List<string> scopes = new List<string>();
        foreach (IConfigurationSection scopeSection in accountSection.GetSection("Scopes").GetChildren()) {
          if (!string.IsNullOrWhiteSpace(scopeSection.Value)) {
            scopes.Add(scopeSection.Value);
          }
        }
        accounts.Add((accountSection["UserName"], accountSection["Password"], scopes.ToArray()));
      }
      this.UseFixedAccounts(accounts.ToArray());
    }

    private static byte[] HashSecret(string secret) {
      if (secret == null) {
        secret = string.Empty;
      }
      return SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }

    private sealed class FixedAccount {

      private readonly byte[] _PasswordHash;
      private readonly string[] _Scopes;

      public FixedAccount(byte[] passwordHash, string[] scopes) {
        _PasswordHash = passwordHash;
        _Scopes = scopes;
      }

      public byte[] PasswordHash {
        get {
          return _PasswordHash;
        }
      }

      public string[] Scopes {
        get {
          return _Scopes;
        }
      }

    }

    #endregion

    /// <summary>
    /// The id under which the server registers itself in the 'AccessTokenManager' (default: 'default').
    /// </summary>
    public string TokenSourceId {
      get {
        return _TokenSourceId;
      }
      set {
        if (string.IsNullOrWhiteSpace(value)) {
          throw new ArgumentException("The token source id must not be empty.", nameof(value));
        }
        _TokenSourceId = value;
      }
    }

    /// <summary>
    /// OPTIONAL: a directory for the encrypted persistence (registered clients and grants survive a restart).
    /// Null (default): all state is held in-memory only.
    /// </summary>
    public string PersistToDir {
      get {
        return _PersistToDir;
      }
      set {
        _PersistToDir = value;
      }
    }

    /// <summary>
    /// OPTIONAL: the secret used to derive the encryption keys of the persistence.
    /// If null, a random key is generated once and stored as key file next to the state file
    /// (this only protects against the disclosure of the state file alone).
    /// </summary>
    public string PersistencePassphrase {
      get {
        return _PersistencePassphrase;
      }
      set {
        _PersistencePassphrase = value;
      }
    }

    /// <summary>
    /// The title of the login and consent page.
    /// </summary>
    public string LoginPageTitle {
      get {
        return _LoginPageTitle;
      }
      set {
        _LoginPageTitle = value;
      }
    }

    /// <summary>
    /// OPTIONAL: a CI color (e.g. '#7b2cbf'), which is applied to the built-in background image of the login pages
    /// (see 'TemplateAuthPageBuilder.BackgroundCiColor'). Null (default): the original image is used.
    /// </summary>
    public string LoginPageBackgroundCiColor {
      get {
        return _LoginPageBackgroundCiColor;
      }
      set {
        _LoginPageBackgroundCiColor = value;
      }
    }

    /// <summary>
    /// OPTIONAL: the url of a custom background image for the login pages (replaces the built-in one).
    /// </summary>
    public string LoginPageCustomBackgroundImageUrl {
      get {
        return _LoginPageCustomBackgroundImageUrl;
      }
      set {
        _LoginPageCustomBackgroundImageUrl = value;
      }
    }

    public TimeSpan AccessTokenLifetime {
      get {
        return _AccessTokenLifetime;
      }
      set {
        if (value <= TimeSpan.Zero) {
          throw new ArgumentException("The lifetime must be positive.", nameof(value));
        }
        _AccessTokenLifetime = value;
      }
    }

    public TimeSpan RefreshTokenLifetime {
      get {
        return _RefreshTokenLifetime;
      }
      set {
        if (value <= TimeSpan.Zero) {
          throw new ArgumentException("The lifetime must be positive.", nameof(value));
        }
        _RefreshTokenLifetime = value;
      }
    }

    /// <summary>
    /// The maximum number of dynamic client registrations (RFC 7591) which are held at the same time (default: 1000).
    /// </summary>
    public int MaxClientRegistrations {
      get {
        return _MaxClientRegistrations;
      }
      set {
        if (value < 0) {
          throw new ArgumentException("The value must not be negative.", nameof(value));
        }
        _MaxClientRegistrations = value;
      }
    }

    /// <summary>
    /// Dynamic client registrations which were not used within this period are removed (default: 30 days).
    /// </summary>
    public TimeSpan UnusedClientRegistrationLifetime {
      get {
        return _UnusedClientRegistrationLifetime;
      }
      set {
        if (value <= TimeSpan.Zero) {
          throw new ArgumentException("The lifetime must be positive.", nameof(value));
        }
        _UnusedClientRegistrationLifetime = value;
      }
    }

    /// <summary>
    /// The hosts which are allowed within redirect URIs of dynamically registered clients
    /// (exact, case-insensitive match - e.g. 'claude.ai', 'chatgpt.com', 'localhost').
    /// Empty (default): all hosts are allowed.
    /// </summary>
    public string[] AllowedRedirectHosts {
      get {
        return _AllowedRedirectHosts;
      }
      set {
        if (value == null) {
          _AllowedRedirectHosts = new string[] { };
        }
        else {
          _AllowedRedirectHosts = value;
        }
      }
    }

    /// <summary>
    /// The redirect path of the built-in public client 'swagger-ui' (resolved against the base url of the
    /// authorize request). Null disables the built-in client. Default: '/docs/oauth2-redirect.html'.
    /// </summary>
    public string SwaggerRedirectPath {
      get {
        return _SwaggerRedirectPath;
      }
      set {
        _SwaggerRedirectPath = value;
      }
    }

    /// <summary>
    /// The scopes of a user whose login result does not contain any scopes (default: none).
    /// </summary>
    public string[] DefaultScopes {
      get {
        return _DefaultScopes;
      }
      set {
        if (value == null) {
          _DefaultScopes = new string[] { };
        }
        else {
          _DefaultScopes = value;
        }
      }
    }

    /// <summary>
    /// The scopes which are published via the RFC 8414 and RFC 9728 metadata (default: none).
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
    /// If true (default), the RFC 9728 protected resource metadata is registered automatically
    /// (only if it was not registered before by the host).
    /// </summary>
    public bool RegisterProtectedResourceMetadata {
      get {
        return _RegisterProtectedResourceMetadata;
      }
      set {
        _RegisterProtectedResourceMetadata = value;
      }
    }

    /// <summary>
    /// Controls the Windows pass-through (Single-Sign-On) login (default: 'Auto').
    /// 'Auto' offers it only, if the host has a Windows authentication scheme ('Negotiate' / 'Windows')
    /// or a 'WindowsOnly' authorization policy registered.
    /// </summary>
    public PassThroughMode EnablePassThrough {
      get {
        return _EnablePassThrough;
      }
      set {
        _EnablePassThrough = value;
      }
    }

    /// <summary>
    /// Validates the options (called during setup).
    /// </summary>
    internal void Validate() {
      if (_ValidateLogin == null) {
        throw new InvalidOperationException(
          "The Cheap OAuth Server requires a credential source ('ValidateLogin', 'UseFixedAccounts' or 'UseAccountsFromConfiguration')."
        );
      }
    }

  }

  /// <summary>
  /// Controls the Windows pass-through (Single-Sign-On) login of the OAuth server.
  /// </summary>
  public enum PassThroughMode {

    /// <summary>
    /// Offered only, if the host has a Windows authentication scheme or a 'WindowsOnly' policy registered.
    /// </summary>
    Auto = 0,

    /// <summary>
    /// Always offered (a missing host setup results in an error page instead of an exception).
    /// </summary>
    On = 1,

    /// <summary>
    /// Never offered.
    /// </summary>
    Off = 2

  }

  public enum CheapOAuthLoginResultKind {
    Invalid = 0,
    Valid = 1,
    BackendUnavailable = 2
  }

  /// <summary>
  /// The result of the credential source of the Cheap OAuth Server.
  /// </summary>
  public sealed class CheapOAuthLoginResult {

    private readonly CheapOAuthLoginResultKind _Kind;
    private readonly string[] _Scopes;
    private readonly string _RetainedSecret;

    private CheapOAuthLoginResult(CheapOAuthLoginResultKind kind, string[] scopes, string retainedSecret) {
      _Kind = kind;
      _Scopes = scopes;
      _RetainedSecret = retainedSecret;
    }

    /// <summary>
    /// The login is valid.
    /// </summary>
    /// <param name="scopes">The scopes of the user (null: 'CheapOAuthOptions.DefaultScopes').</param>
    /// <param name="retainedSecret">
    /// OPTIONAL: a secret which is kept server-side within the grants (encrypted when persisted), so that the
    /// application can pass it through to a backend (e.g. the password for a CalDAV server).
    /// </param>
    public static CheapOAuthLoginResult Valid(string[] scopes = null, string retainedSecret = null) {
      return new CheapOAuthLoginResult(CheapOAuthLoginResultKind.Valid, scopes, retainedSecret);
    }

    /// <summary>
    /// The credentials are invalid.
    /// </summary>
    public static CheapOAuthLoginResult Invalid() {
      return new CheapOAuthLoginResult(CheapOAuthLoginResultKind.Invalid, null, null);
    }

    /// <summary>
    /// The backend which validates the credentials is currently not available.
    /// </summary>
    public static CheapOAuthLoginResult BackendUnavailable() {
      return new CheapOAuthLoginResult(CheapOAuthLoginResultKind.BackendUnavailable, null, null);
    }

    public CheapOAuthLoginResultKind Kind {
      get {
        return _Kind;
      }
    }

    public string[] Scopes {
      get {
        return _Scopes;
      }
    }

    public string RetainedSecret {
      get {
        return _RetainedSecret;
      }
    }

  }

}
