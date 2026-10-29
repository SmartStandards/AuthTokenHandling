using AuthTokenHandling.TestApp.Model;
using AuthTokenHandling.TestApp.Persistence;
using AuthTokenHandling.TestApp.Services;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AuthTokenHandling.TestApp.Bridge {

  /// <summary>
  /// Dispatches all requests of the WebView2 UI ('{id, cmd, args}') and replies with '{id, ok, result, error}'.
  /// Commands which require the UI thread (dialogs, interactive OAuth) are executed there, all other
  /// commands (HTTP calls, factories) are executed on a worker thread to keep the UI responsive.
  /// </summary>
  internal sealed class HostBridge {

    private static readonly HashSet<string> _UiThreadCommands = new HashSet<string>(StringComparer.Ordinal) {
      "getState", "saveProfile", "deleteProfile", "selectProfile", "saveTokens",
      "exportProfiles", "importProfiles", "openBrowser", "copyToClipboard", "oauthInteractive"
    };

    private readonly Form _Owner;
    private readonly WebView2 _WebView;
    private readonly SettingsStore _Store;

    public HostBridge(Form owner, WebView2 webView, SettingsStore store) {

      _Owner = owner;
      _WebView = webView;
      _Store = store;

    }

    private AppSettings Settings {
      get {
        return _Store.Current;
      }
    }

    /// <summary>
    /// Entry point for messages posted by the UI.
    /// </summary>
    public void OnWebMessageReceived(object sender, CoreWebView2WebMessageReceivedEventArgs e) {

      JObject message = JObject.Parse(e.WebMessageAsJson);
      long id = message.Value<long>("id");
      string command = message.Value<string>("cmd");
      JObject args = message["args"] as JObject;
      if (args == null) {
        args = new JObject();
      }

      //leave the WebView2 event handler before executing (modal dialogs must not be opened from within it)
      _Owner.BeginInvoke(new Action(() => this.Dispatch(id, command, args)));

    }

    /// <summary>
    /// Executes a command on the appropriate thread and posts the reply.
    /// </summary>
    private void Dispatch(long id, string command, JObject args) {

      if (_UiThreadCommands.Contains(command)) {
        this.ExecuteAndReply(id, command, args);
        return;
      }

      Task.Run(() => {
        JToken result = null;
        string error = null;
        try {
          result = this.ExecuteWorkerCommand(command, args);
        } catch (Exception ex) {
          //bridge boundary: every failure is reported to the UI (instead of terminating the host)
          error = DescribeException(ex);
        }
        _Owner.BeginInvoke(new Action(() => this.PostReply(id, error == null, result, error)));
      });

    }

    /// <summary>
    /// Executes a UI thread command and posts the reply.
    /// </summary>
    private void ExecuteAndReply(long id, string command, JObject args) {

      JToken result;
      try {
        result = this.ExecuteUiCommand(command, args);
      } catch (Exception ex) {
        //bridge boundary: every failure is reported to the UI (instead of terminating the host)
        this.PostReply(id, false, null, DescribeException(ex));
        return;
      }

      this.PostReply(id, true, result, null);
    }

    /// <summary>
    /// Commands, which are executed on the UI thread.
    /// </summary>
    private JToken ExecuteUiCommand(string command, JObject args) {

      switch (command) {

        case "getState":
          return this.BuildState();

        case "saveProfile":
          this.SaveProfile(ReadProfile(args), args.Value<string>("oldName"));
          return this.BuildState();

        case "deleteProfile":
          this.DeleteProfile(args.Value<string>("name"));
          return this.BuildState();

        case "selectProfile":
          this.Settings.CurrentProfileName = args.Value<string>("name");
          _Store.Save();
          return JValue.CreateNull();

        case "saveTokens":
          this.Settings.LastTokens = args["tokens"].ToObject<TokenSet>();
          _Store.Save();
          return JValue.CreateNull();

        case "exportProfiles":
          return new JValue(this.ExportProfiles(args["names"] as JArray));

        case "importProfiles":
          return this.ImportProfiles();

        case "openBrowser":
          OpenBrowser(args.Value<string>("url"));
          return JValue.CreateNull();

        case "copyToClipboard":
          string text = args.Value<string>("text");
          if (string.IsNullOrEmpty(text)) {
            Clipboard.Clear();
          } else {
            Clipboard.SetText(text);
          }
          return JValue.CreateNull();

        case "oauthInteractive":
          return OAuthFlowRunner.RunInteractiveFlow(ReadProfile(args), _Owner);

        default:
          throw new NotSupportedException($"Unknown command '{command}'.");
      }

    }

    /// <summary>
    /// Commands, which are executed on a worker thread (factories, HTTP calls).
    /// </summary>
    private JToken ExecuteWorkerCommand(string command, JObject args) {

      switch (command) {

        case "describeIssuer":
          return FactoryRunner.DescribeIssuer(ReadConfig(args));

        case "describeIntrospector":
          return FactoryRunner.DescribeIntrospector(ReadConfig(args));

        case "issueToken":
          return FactoryRunner.IssueToken(
            ReadConfig(args),
            args.Value<string>("subject"), args.Value<string>("audience"),
            args.Value<string>("scopes"), args.Value<string>("claimsJson")
          );

        case "introspectToken":
          return FactoryRunner.IntrospectToken(ReadConfig(args), args.Value<string>("token"));

        case "decodeJwt":
          return JwtInspector.Decode(args.Value<string>("token"));

        case "describeProvider":
          return OAuthFlowRunner.DescribeProvider(ReadProfile(args));

        case "oauthAuthorizeUrl":
          return new JValue(OAuthFlowRunner.GenerateAuthorizeUrl(ReadProfile(args)));

        case "oauthFromRedirectedUrl":
          return OAuthFlowRunner.TokenFromRedirectedUrl(ReadProfile(args), args.Value<string>("url"));

        case "oauthExchangeCode":
          return OAuthFlowRunner.ExchangeCode(ReadProfile(args), args.Value<string>("code"));

        case "oauthClientCredentials":
          return OAuthFlowRunner.RunClientCredentialsFlow(ReadProfile(args));

        case "oauthRefresh":
          return OAuthFlowRunner.RunRefreshFlow(ReadProfile(args), args.Value<string>("refreshToken"));

        case "oauthValidate":
          return OAuthFlowRunner.ValidateViaProvider(ReadProfile(args), args.Value<string>("token"));

        case "oauthResolveSubject":
          return OAuthFlowRunner.ResolveSubject(ReadProfile(args), args.Value<string>("token"), args.Value<string>("idToken"));

        default:
          throw new NotSupportedException($"Unknown command '{command}'.");
      }

    }

    #region " State & Profiles "

    /// <summary>
    /// Builds the complete UI state (profiles, selection, tokens and the wellknown option lists).
    /// </summary>
    private JObject BuildState() {

      JObject state = new JObject();
      state["profiles"] = JArray.FromObject(this.Settings.Profiles);
      state["currentProfileName"] = this.Settings.CurrentProfileName;
      state["lastTokens"] = JObject.FromObject(this.Settings.LastTokens);
      state["settingsFilePath"] = _Store.FilePath;
      state["defaultConfig"] = JObject.FromObject(new AuthTokenConfig());

      state["issueModes"] = new JArray(
        WellknownIssuingModes.RAW_INPUT,
        WellknownIssuingModes.HTTP_GET,
        WellknownIssuingModes.LOCAL_BASICAUTH_GENERATION,
        WellknownIssuingModes.LOCAL_JWT_GENERATION,
        WellknownIssuingModes.OAUTH_IMPLICIT_FLOW,
        WellknownIssuingModes.OAUTH_CIBA_CODEGRAND,
        WellknownIssuingModes.OAUTH_CIBA_CODEGRAND_HTTPGETONLY
      );

      state["validationModes"] = new JArray(
        WellknownValidationModes.IMPLICIT_WHEN_USED,
        WellknownValidationModes.LOCAL_JWT_VALIDATION,
        WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT,
        WellknownValidationModes.OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY,
        WellknownValidationModes.GITHUB_VALIDATION_ENDPOINT
      );

      state["providerTypes"] = new JArray(OAuthFlowRunner.ProviderTypes);
      state["jwsAlgorithms"] = new JArray(Enum.GetNames(typeof(Jose.JwsAlgorithm)));

      return state;
    }

    /// <summary>
    /// Inserts or replaces (and optionally renames) a profile.
    /// </summary>
    private void SaveProfile(AuthTokenConfigProfile profile, string oldName) {

      SettingsStore.NormalizeProfile(profile);
      profile.Name = profile.Name.Trim();

      List<AuthTokenConfigProfile> profiles = new List<AuthTokenConfigProfile>(this.Settings.Profiles);

      string keyToReplace = oldName;
      if (string.IsNullOrWhiteSpace(keyToReplace)) {
        keyToReplace = profile.Name;
      }

      bool nameChanged = !string.Equals(keyToReplace, profile.Name, StringComparison.OrdinalIgnoreCase);
      if (nameChanged && IndexOf(profiles, profile.Name) >= 0) {
        throw new InvalidOperationException($"A profile named '{profile.Name}' already exists.");
      }

      int index = IndexOf(profiles, keyToReplace);
      if (index >= 0) {
        profiles[index] = profile;
      } else {
        profiles.Add(profile);
      }

      this.Settings.Profiles = profiles.ToArray();
      this.Settings.CurrentProfileName = profile.Name;
      _Store.Save();

    }

    /// <summary>
    /// Removes a profile (the store re-creates the defaults, if the last one was removed).
    /// </summary>
    private void DeleteProfile(string name) {

      List<AuthTokenConfigProfile> profiles = new List<AuthTokenConfigProfile>(this.Settings.Profiles);

      int index = IndexOf(profiles, name);
      if (index >= 0) {
        profiles.RemoveAt(index);
      }

      this.Settings.Profiles = profiles.ToArray();
      SettingsStore.Normalize(this.Settings);
      _Store.Save();

    }

    private static int IndexOf(List<AuthTokenConfigProfile> profiles, string name) {

      for (int i = 0; i < profiles.Count; i++) {
        if (string.Equals(profiles[i].Name, name, StringComparison.OrdinalIgnoreCase)) {
          return i;
        }
      }

      return -1;
    }

    #endregion

    #region " Import & Export "

    /// <summary>
    /// Exports the given profiles (or all, if no names are given) into a JSON file chosen by the user.
    /// A single profile is exported as single object, multiple profiles as array.
    /// Returns the file path or null, if the user cancelled.
    /// </summary>
    private string ExportProfiles(JArray names) {

      List<AuthTokenConfigProfile> selection = new List<AuthTokenConfigProfile>();
      foreach (AuthTokenConfigProfile profile in this.Settings.Profiles) {
        if (names == null || names.Count == 0 || ContainsName(names, profile.Name)) {
          selection.Add(profile);
        }
      }

      if (selection.Count == 0) {
        throw new InvalidOperationException("No profiles selected for export.");
      }

      string json;
      string suggestedName;
      if (selection.Count == 1) {
        json = JsonConvert.SerializeObject(selection[0], Formatting.Indented);
        suggestedName = MakeFileName(selection[0].Name) + ".authtokenconfig.json";
      } else {
        json = JsonConvert.SerializeObject(selection.ToArray(), Formatting.Indented);
        suggestedName = "AuthTokenConfigs.json";
      }

      using (SaveFileDialog dialog = new SaveFileDialog()) {
        dialog.Title = "Export AuthTokenConfig(s)";
        dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*";
        dialog.FileName = suggestedName;
        if (dialog.ShowDialog(_Owner) != DialogResult.OK) {
          return null;
        }
        File.WriteAllText(dialog.FileName, json);
        return dialog.FileName;
      }

    }

    /// <summary>
    /// Imports profiles from JSON files chosen by the user. Supported shapes: an array of profiles, a single
    /// profile ('{ Name, Config, OAuth }'), a complete settings file ('{ Profiles: [...] }') or a bare 'AuthTokenConfig'.
    /// Name collisions are resolved by appending a counter.
    /// </summary>
    private JObject ImportProfiles() {

      string[] fileNames;
      using (OpenFileDialog dialog = new OpenFileDialog()) {
        dialog.Title = "Import AuthTokenConfig(s)";
        dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*";
        dialog.Multiselect = true;
        if (dialog.ShowDialog(_Owner) != DialogResult.OK) {
          JObject cancelled = this.BuildState();
          cancelled["importedNames"] = new JArray();
          return cancelled;
        }
        fileNames = dialog.FileNames;
      }

      List<AuthTokenConfigProfile> profiles = new List<AuthTokenConfigProfile>(this.Settings.Profiles);
      JArray importedNames = new JArray();

      foreach (string fileName in fileNames) {
        JToken root;
        try {
          root = JToken.Parse(File.ReadAllText(fileName));
        } catch (JsonReaderException ex) {
          throw new InvalidOperationException($"'{Path.GetFileName(fileName)}' contains no valid JSON: {ex.Message}");
        }

        foreach (AuthTokenConfigProfile imported in ParseImport(root, Path.GetFileNameWithoutExtension(fileName))) {
          SettingsStore.NormalizeProfile(imported);
          imported.Name = MakeUniqueName(profiles, imported.Name.Trim());
          profiles.Add(imported);
          importedNames.Add(imported.Name);
        }
      }

      this.Settings.Profiles = profiles.ToArray();
      if (importedNames.Count > 0) {
        this.Settings.CurrentProfileName = importedNames[0].Value<string>();
      }
      _Store.Save();

      JObject state = this.BuildState();
      state["importedNames"] = importedNames;
      return state;
    }

    /// <summary>
    /// Detects the shape of an imported JSON document and converts it into profiles.
    /// </summary>
    private static List<AuthTokenConfigProfile> ParseImport(JToken root, string fallbackName) {

      List<AuthTokenConfigProfile> result = new List<AuthTokenConfigProfile>();

      if (root is JArray) {
        foreach (JToken item in (JArray)root) {
          result.AddRange(ParseImport(item, fallbackName));
        }
        return result;
      }

      JObject obj = root as JObject;
      if (obj == null) {
        throw new InvalidOperationException("The imported JSON must be an object or an array.");
      }

      JToken profilesToken = GetPropertyIgnoreCase(obj, "Profiles");
      if (profilesToken is JArray) {
        return ParseImport(profilesToken, fallbackName);
      }

      if (GetPropertyIgnoreCase(obj, "Config") is JObject) {
        result.Add(obj.ToObject<AuthTokenConfigProfile>());
        return result;
      }

      //bare 'AuthTokenConfig'
      AuthTokenConfigProfile profile = new AuthTokenConfigProfile();
      profile.Config = obj.ToObject<AuthTokenConfig>();
      if (!string.IsNullOrWhiteSpace(profile.Config.DisplayLabel)) {
        profile.Name = profile.Config.DisplayLabel;
      } else {
        profile.Name = fallbackName;
      }
      result.Add(profile);

      return result;
    }

    private static JToken GetPropertyIgnoreCase(JObject obj, string name) {

      JProperty property = obj.Property(name, StringComparison.OrdinalIgnoreCase);
      if (property == null) {
        return null;
      }

      return property.Value;
    }

    private static string MakeUniqueName(List<AuthTokenConfigProfile> profiles, string name) {

      if (string.IsNullOrWhiteSpace(name)) {
        name = "Imported";
      }

      string candidate = name;
      int counter = 2;
      while (IndexOf(profiles, candidate) >= 0) {
        candidate = name + " (" + counter + ")";
        counter++;
      }

      return candidate;
    }

    private static bool ContainsName(JArray names, string name) {

      foreach (JToken entry in names) {
        if (string.Equals(entry.Value<string>(), name, StringComparison.OrdinalIgnoreCase)) {
          return true;
        }
      }

      return false;
    }

    private static string MakeFileName(string name) {

      char[] invalidChars = Path.GetInvalidFileNameChars();
      char[] chars = name.ToCharArray();
      for (int i = 0; i < chars.Length; i++) {
        if (Array.IndexOf(invalidChars, chars[i]) >= 0) {
          chars[i] = '_';
        }
      }

      return new string(chars);
    }

    #endregion

    #region " Helpers "

    private static AuthTokenConfigProfile ReadProfile(JObject args) {

      JToken profileToken = args["profile"];
      if (profileToken == null || profileToken.Type != JTokenType.Object) {
        throw new ArgumentException("No profile given!");
      }

      AuthTokenConfigProfile profile = profileToken.ToObject<AuthTokenConfigProfile>();
      SettingsStore.NormalizeProfile(profile);
      return profile;
    }

    private static AuthTokenConfig ReadConfig(JObject args) {

      JToken configToken = args["config"];
      if (configToken == null || configToken.Type != JTokenType.Object) {
        throw new ArgumentException("No AuthTokenConfig given!");
      }

      return configToken.ToObject<AuthTokenConfig>();
    }

    /// <summary>
    /// Builds a message, which includes inner exceptions (factories often wrap the root cause).
    /// </summary>
    private static string DescribeException(Exception ex) {

      string message = ex.GetType().Name + ": " + ex.Message;

      Exception inner = ex.InnerException;
      while (inner != null) {
        message = message + "\n  -> " + inner.GetType().Name + ": " + inner.Message;
        inner = inner.InnerException;
      }

      return message;
    }

    private static void OpenBrowser(string url) {

      Uri target;
      if (!Uri.TryCreate(url, UriKind.Absolute, out target)) {
        throw new ArgumentException($"'{url}' is no valid absolute url.");
      }

      if (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps) {
        throw new ArgumentException("Only http(s) urls can be opened.");
      }

      ProcessStartInfo startInfo = new ProcessStartInfo(target.AbsoluteUri);
      startInfo.UseShellExecute = true;
      Process.Start(startInfo);

    }

    /// <summary>
    /// Posts the reply for a request to the UI.
    /// </summary>
    private void PostReply(long id, bool ok, JToken result, string error) {

      if (_WebView.CoreWebView2 == null) {
        return;
      }

      JObject reply = new JObject();
      reply["id"] = id;
      reply["ok"] = ok;
      if (result == null) {
        reply["result"] = JValue.CreateNull();
      } else {
        reply["result"] = result;
      }
      reply["error"] = error;

      _WebView.CoreWebView2.PostWebMessageAsJson(reply.ToString(Formatting.None));

    }

    #endregion

  }

}
