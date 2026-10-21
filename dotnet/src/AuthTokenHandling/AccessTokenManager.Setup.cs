using System;
using System.Collections.Generic;
using System.Linq;

namespace Security.AccessTokenHandling {

  public static partial class AccessTokenManager {

    private static List<PersistenceSetting> _PersistenceSettings = new List<PersistenceSetting>();
    private static ITokenPersistenceProvider _DefaultPersistenceProvider = null;

    /// <summary>
    /// Wildcard for 'all token sources' (persistence settings).
    /// </summary>
    public const string AllTokenSources = "*";

    private enum PersistedTokenKind {
      AccessToken,
      RefreshToken,
      IdToken
    }

    /// <summary>
    /// One 'Enable...Persistence' call.
    /// </summary>
    private class PersistenceSetting {
      public string TokenSourceId;
      public PersistedTokenKind Kind;
      public bool UserScope;
      public Func<string> CustomScope;
      public ITokenPersistenceProvider Provider;
    }

    /// <summary>
    /// A resolved persistence location (one file / one record contains all enabled tokens of a source).
    /// </summary>
    private class PersistenceTarget {
      public ITokenPersistenceProvider Provider;
      public bool UserScope;
      public string CustomScope;
      public bool AccessToken;
      public bool RefreshToken;
      public bool IdToken;
    }

    /// <summary>
    /// Configures the token supply (token sources, persistence, relay behavior).
    /// Can be called several times (additive).
    /// </summary>
    public static void ConfigureTokenSupply(Action<TokenSupplyConfigurator> configurationMethod) {
      if (configurationMethod == null) {
        throw new ArgumentNullException(nameof(configurationMethod));
      }
      configurationMethod.Invoke(new TokenSupplyConfigurator());
    }

    /// <summary>
    /// Options for 'ConfigureTokenSupply'.
    /// </summary>
    public class TokenSupplyConfigurator {

      internal TokenSupplyConfigurator() {
      }

      /// <summary>
      /// Registers (or replaces) a token source. Issuer and introspector are created lazily via
      /// 'IssuerFactory' and 'IntrospectorFactory'.
      /// </summary>
      public void ApplyFromConfiguration(string tokenSourceId, AuthTokenConfig config) {
        if (config == null) {
          throw new ArgumentNullException(nameof(config));
        }
        TokenSourceRegistration registration = new TokenSourceRegistration();
        registration.Config = config;
        lock (_SyncRoot) {
          _Registrations[NormalizeId(tokenSourceId)] = registration;
          _SuppliedTokens.Remove(NormalizeId(tokenSourceId));
        }
      }

      /// <summary>
      /// Registers (or replaces) several token sources.
      /// </summary>
      public void ApplyFromConfiguration(IDictionary<string, AuthTokenConfig> authTokenConfigsByTokenSourceId) {
        if (authTokenConfigsByTokenSourceId == null) {
          throw new ArgumentNullException(nameof(authTokenConfigsByTokenSourceId));
        }
        foreach (KeyValuePair<string, AuthTokenConfig> entry in authTokenConfigsByTokenSourceId) {
          this.ApplyFromConfiguration(entry.Key, entry.Value);
        }
      }

      /// <summary>
      /// Registers a token source with explicitly given issuer and/or introspector (instead of the factories).
      /// </summary>
      public void ApplyCustomTokenSource(string tokenSourceId, IAccessTokenIssuer issuer, IAccessTokenIntrospector introspector, AuthTokenConfig config = null) {
        TokenSourceRegistration registration = new TokenSourceRegistration();
        registration.Config = config;
        registration.Issuer = issuer;
        registration.IssuerCreated = true;
        registration.Introspector = introspector;
        registration.IntrospectorCreated = true;
        lock (_SyncRoot) {
          _Registrations[NormalizeId(tokenSourceId)] = registration;
          _SuppliedTokens.Remove(NormalizeId(tokenSourceId));
        }
      }

      /// <summary>
      /// Tokens of this token source are never pushed into the register by the validator and never relayed
      /// to outgoing calls (the external 'RawTokenExposal' hook is not affected).
      /// </summary>
      public void DisableTokenRelay(string tokenSourceId) {
        lock (_SyncRoot) {
          _NonRelayableTokenSourceIds.Add(NormalizeId(tokenSourceId));
        }
      }

      /// <summary>
      /// OPTIONAL: a public base url which is used instead of the '{RequestBaseUrl}' placeholder
      /// (for proxies without forwarded headers and for outgoing calls without a request).
      /// </summary>
      public void UsePublicBaseUrl(string publicBaseUrl) {
        if (publicBaseUrl == null) {
          _PublicBaseUrl = null;
        }
        else {
          _PublicBaseUrl = publicBaseUrl.TrimEnd('/');
        }
      }

      /// <summary>
      /// Configures the file based default persistence provider (used when 'persistenceProvider' is null).
      /// </summary>
      /// <param name="encryptionPassphrase">Secret used to derive the encryption keys.</param>
      /// <param name="applicationName">Name of the application folder (null: name of the entry assembly).</param>
      public void ConfigureDefaultPersistence(string encryptionPassphrase, string applicationName = null) {
        lock (_SyncRoot) {
          _DefaultPersistenceProvider = new FileTokenPersistenceProvider(encryptionPassphrase, applicationName);
        }
      }

      /// <summary>
      /// Enables the persistence of access tokens obtained by the manager (opt-in).
      /// </summary>
      /// <param name="tokenSourceId">"*" (all token sources) or one token source id.</param>
      /// <param name="userScope">true: per application runtime user, false: machine wide.</param>
      /// <param name="customScope">Additional isolation scope evaluated at runtime; if it returns null/empty, nothing is persisted.</param>
      /// <param name="persistenceProvider">null: file based default.</param>
      public void EnableAuthTokenPersistence(string tokenSourceId, bool userScope = true, Func<string> customScope = null, ITokenPersistenceProvider persistenceProvider = null) {
        AddPersistenceSetting(tokenSourceId, PersistedTokenKind.AccessToken, userScope, customScope, persistenceProvider);
      }

      /// <summary>
      /// Enables the persistence of id tokens obtained by the manager (opt-in). Parameters see 'EnableAuthTokenPersistence'.
      /// </summary>
      public void EnableIdTokenPersistence(string tokenSourceId, bool userScope = true, Func<string> customScope = null, ITokenPersistenceProvider persistenceProvider = null) {
        AddPersistenceSetting(tokenSourceId, PersistedTokenKind.IdToken, userScope, customScope, persistenceProvider);
      }

      /// <summary>
      /// Enables the persistence of refresh tokens obtained by the manager (opt-in). Parameters see 'EnableAuthTokenPersistence'.
      /// </summary>
      public void EnableRefreshTokenPersistence(string tokenSourceId, bool userScope = true, Func<string> customScope = null, ITokenPersistenceProvider persistenceProvider = null) {
        AddPersistenceSetting(tokenSourceId, PersistedTokenKind.RefreshToken, userScope, customScope, persistenceProvider);
      }

      private static void AddPersistenceSetting(string tokenSourceId, PersistedTokenKind kind, bool userScope, Func<string> customScope, ITokenPersistenceProvider persistenceProvider) {
        PersistenceSetting setting = new PersistenceSetting();
        if (tokenSourceId == AllTokenSources) {
          setting.TokenSourceId = AllTokenSources;
        }
        else {
          setting.TokenSourceId = NormalizeId(tokenSourceId);
        }
        setting.Kind = kind;
        setting.UserScope = userScope;
        setting.CustomScope = customScope;
        setting.Provider = persistenceProvider;
        lock (_SyncRoot) {
          _PersistenceSettings.Add(setting);
        }
      }

    }

    /// <summary>
    /// Resets the complete manager state (intended for tests).
    /// </summary>
    internal static void Reset() {
      lock (_SyncRoot) {
        _MappingsByLogicalName.Clear();
        _AnonymousLogicalNames.Clear();
        _ScopesRequiredForAll.Clear();
        _ScopesRequiredByLogicalName.Clear();
        _TokenSourceIdsByIssuer.Clear();
        _Registrations.Clear();
        _NonRelayableTokenSourceIds.Clear();
        _Register.Clear();
        _SuppliedTokens.Clear();
        _PersistenceSettings.Clear();
        _DefaultPersistenceProvider = null;
        _PublicBaseUrl = null;
      }
      _MatchedTokenSourceId = null;
      _CurrentApiGroupName = null;
      _CurrentAdditionalLogicalNames = null;
    }

    /// <summary>
    /// Evaluates the persistence settings for a token source and merges them per location
    /// (provider + userScope + customScope), so that one record contains all enabled tokens.
    /// Settings whose custom scope evaluates to null/empty are skipped (no persistence without isolation).
    /// </summary>
    private static PersistenceTarget[] GetPersistenceTargets(string resolvedId) {
      PersistenceSetting[] settings;
      lock (_SyncRoot) {
        settings = _PersistenceSettings.Where(
          (s) => s.TokenSourceId == AllTokenSources || s.TokenSourceId.Equals(resolvedId, StringComparison.OrdinalIgnoreCase)
        ).ToArray();
      }

      List<PersistenceTarget> targets = new List<PersistenceTarget>();
      foreach (PersistenceSetting setting in settings) {

        string customScope = string.Empty;
        if (setting.CustomScope != null) {
          customScope = setting.CustomScope.Invoke();
          if (string.IsNullOrEmpty(customScope)) {
            continue;
          }
        }

        ITokenPersistenceProvider provider = setting.Provider;
        if (provider == null) {
          provider = GetDefaultPersistenceProvider();
        }

        PersistenceTarget target = targets.FirstOrDefault(
          (t) => ReferenceEquals(t.Provider, provider) && t.UserScope == setting.UserScope && t.CustomScope == customScope
        );
        if (target == null) {
          target = new PersistenceTarget();
          target.Provider = provider;
          target.UserScope = setting.UserScope;
          target.CustomScope = customScope;
          targets.Add(target);
        }

        if (setting.Kind == PersistedTokenKind.AccessToken) {
          target.AccessToken = true;
        }
        else if (setting.Kind == PersistedTokenKind.RefreshToken) {
          target.RefreshToken = true;
        }
        else {
          target.IdToken = true;
        }
      }
      return targets.ToArray();
    }

    /// <summary>
    /// Returns the file based default provider. If 'ConfigureDefaultPersistence' was not called, a passphrase derived
    /// from machine and user name is used (protects against casual reading only - configure an own secret for more!).
    /// </summary>
    private static ITokenPersistenceProvider GetDefaultPersistenceProvider() {
      lock (_SyncRoot) {
        if (_DefaultPersistenceProvider == null) {
          _DefaultPersistenceProvider = new FileTokenPersistenceProvider(
            "ATH|" + Environment.MachineName + "|" + Environment.UserName
          );
        }
        return _DefaultPersistenceProvider;
      }
    }

  }

}
