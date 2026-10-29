using AuthTokenHandling.TestApp.Model;
using Newtonsoft.Json;
using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.IO;

namespace AuthTokenHandling.TestApp.Persistence {

  /// <summary>
  /// Loads and saves the per-user settings file ('%APPDATA%\SmartStandards\AuthTest\settings.json').
  /// </summary>
  internal sealed class SettingsStore {

    private static readonly string _SettingsDirectory = Path.Combine(
      Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SmartStandards", "AuthTest"
    );

    private static readonly string _LocalDataDirectory = Path.Combine(
      Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SmartStandards", "AuthTest"
    );

    private readonly string _FilePath;
    private AppSettings _Current;

    public SettingsStore() {

      _FilePath = Path.Combine(_SettingsDirectory, "settings.json");
      _Current = this.Load();

    }

    /// <summary>
    /// Directory for machine-local (non roaming) data such as the WebView2 user data folder.
    /// </summary>
    public static string LocalDataDirectory {
      get {
        return _LocalDataDirectory;
      }
    }

    public string FilePath {
      get {
        return _FilePath;
      }
    }

    public AppSettings Current {
      get {
        return _Current;
      }
    }

    /// <summary>
    /// Writes the current settings to disk (atomically via a temp file).
    /// </summary>
    public void Save() {

      Directory.CreateDirectory(_SettingsDirectory);
      string json = JsonConvert.SerializeObject(_Current, Formatting.Indented);
      string tempFilePath = _FilePath + ".tmp";
      File.WriteAllText(tempFilePath, json);
      File.Move(tempFilePath, _FilePath, true);

    }

    /// <summary>
    /// Reads the settings file. A corrupt file is copied to '*.corrupt' and replaced by default settings.
    /// </summary>
    private AppSettings Load() {

      AppSettings settings = null;

      if (File.Exists(_FilePath)) {
        string json = File.ReadAllText(_FilePath);
        try {
          settings = JsonConvert.DeserializeObject<AppSettings>(json);
        } catch (JsonException) {
          File.Copy(_FilePath, _FilePath + ".corrupt", true);
          settings = null;
        }
      }

      if (settings == null) {
        settings = new AppSettings();
      }

      Normalize(settings);
      return settings;
    }

    /// <summary>
    /// Replaces null values (which can occur in manually edited or imported files) by empty defaults
    /// and ensures, that at least the demo profiles are present.
    /// </summary>
    public static void Normalize(AppSettings settings) {

      if (settings.Profiles == null || settings.Profiles.Length == 0) {
        settings.Profiles = CreateDefaultProfiles();
      }

      foreach (AuthTokenConfigProfile profile in settings.Profiles) {
        NormalizeProfile(profile);
      }

      if (settings.LastTokens == null) {
        settings.LastTokens = new TokenSet();
      }

      if (settings.CurrentProfileName == null || !ContainsProfile(settings, settings.CurrentProfileName)) {
        settings.CurrentProfileName = settings.Profiles[0].Name;
      }

    }

    /// <summary>
    /// Replaces null values within a single profile by defaults.
    /// </summary>
    public static void NormalizeProfile(AuthTokenConfigProfile profile) {

      if (string.IsNullOrWhiteSpace(profile.Name)) {
        profile.Name = "Unnamed";
      }

      if (profile.Config == null) {
        profile.Config = new AuthTokenConfig();
      }

      if (profile.OAuth == null) {
        profile.OAuth = new OAuthFlowSettings();
      }

      if (profile.OAuth.ProviderConfiguration == null) {
        profile.OAuth.ProviderConfiguration = new Dictionary<string, string>();
      }

      //migration of the former demo profile (the client id 'AuthTest' is unknown to the Cheap OAuth Server)
      bool isFormerDemoProfile = (
        string.Equals(profile.Config.ClientId, "AuthTest", StringComparison.Ordinal) &&
        string.Equals(profile.Config.AuthEndpointUrl, "http://localhost:55882/oauth2/authorize", StringComparison.OrdinalIgnoreCase)
      );
      if (isFormerDemoProfile) {
        profile.Config.ClientId = "swagger-ui";
        profile.OAuth.RedirectUri = "http://localhost:55882/docs/oauth2-redirect.html";
        profile.OAuth.ProviderConfiguration["pkce"] = "true";
      }

    }

    private static bool ContainsProfile(AppSettings settings, string name) {

      foreach (AuthTokenConfigProfile profile in settings.Profiles) {
        if (string.Equals(profile.Name, name, StringComparison.OrdinalIgnoreCase)) {
          return true;
        }
      }

      return false;
    }

    /// <summary>
    /// Creates the out-of-the-box profiles (local JWT and the 'Cheap OAuth Server' of the DemoWebService).
    /// </summary>
    private static AuthTokenConfigProfile[] CreateDefaultProfiles() {

      AuthTokenConfigProfile localJwt = new AuthTokenConfigProfile();
      localJwt.Name = "Local JWT (Demo)";
      localJwt.Config.DisplayLabel = "Local JWT";
      localJwt.Config.IssueMode = WellknownIssuingModes.LOCAL_JWT_GENERATION;
      localJwt.Config.JwtSelfSignKey = "TheBigAndMightyFoo";
      localJwt.Config.JwtSelfSignAlg = "HS256";
      localJwt.Config.JwtExpMinutes = 60;
      localJwt.Config.ValidationMode = WellknownValidationModes.LOCAL_JWT_VALIDATION;
      localJwt.Config.JwtValidationKey = "TheBigAndMightyFoo";
      localJwt.Config.Claims = new Dictionary<string, string>();
      localJwt.Config.Claims["iss"] = "AuthTest";

      AuthTokenConfigProfile cheapOAuth = new AuthTokenConfigProfile();
      cheapOAuth.Name = "Cheap OAuth (DemoWebService)";
      cheapOAuth.Config.DisplayLabel = "Cheap OAuth Server";
      cheapOAuth.Config.IssueMode = WellknownIssuingModes.OAUTH_CIBA_CODEGRAND;
      //the built-in public client of the Cheap OAuth Server (no registration required) - it only accepts
      //redirects to '<host of the authorize request>/docs/oauth2-redirect.html', which is intercepted by the embedded browser
      cheapOAuth.Config.ClientId = "swagger-ui";
      cheapOAuth.Config.AuthEndpointUrl = "http://localhost:55882/oauth2/authorize";
      cheapOAuth.Config.RetrieveEndpointUrl = "http://localhost:55882/oauth2/token";
      cheapOAuth.Config.JwtSelfSignAlg = "HS256";
      cheapOAuth.Config.ValidationMode = WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT;
      cheapOAuth.Config.ValidationEndpointUrl = "http://localhost:55882/oauth2/introspect";
      cheapOAuth.OAuth.Scopes = "demo";
      cheapOAuth.OAuth.RedirectUri = "http://localhost:55882/docs/oauth2-redirect.html";

      //the Cheap OAuth Server requires PKCE (S256) for the code flow
      cheapOAuth.OAuth.ProviderConfiguration["pkce"] = "true";

      return new AuthTokenConfigProfile[] { localJwt, cheapOAuth };
    }

  }

}
