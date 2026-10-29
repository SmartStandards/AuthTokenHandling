using HtmlDocGen.CopyForAuthTokenHandling;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Default 'IAuthPageBuilder', which renders all OAuth pages (login, pass-through login, consent, error,
  /// token display) via the embedded HtmlDocGen template engine.
  /// All built-in templates can be replaced partially by passing 'templateOverrides' (keyed by template name),
  /// see 'GetDefaultTemplates()' for the available template names and the default markup.
  /// </summary>
  public partial class TemplateAuthPageBuilder : IAuthPageBuilder {

    public const string HeadTemplateName = "Head";
    public const string LayoutTemplateName = "Layout";
    public const string HiddenFieldsTemplateName = "HiddenFields";
    public const string LoginTemplateName = "Login";
    public const string PassThroughLoginTemplateName = "PassThroughLogin";
    public const string ConsentTemplateName = "Consent";
    public const string ErrorTemplateName = "Error";
    public const string TokenDisplayTemplateName = "TokenDisplay";
    public const string CustomTemplateName = "Custom";

    private readonly TemplateEngine _Engine;
    private readonly string _Title;
    private readonly string _Logo;
    private readonly string _PortalUrl;
    private readonly string _LegalUrl;
    private readonly string _DefaultBgColor;
    private readonly string _DefaultTextColor;
    private readonly string _DefaultBgColorDarkmode;
    private readonly string _DefaultTextColorDarkmode;

    /// <summary>
    /// Creates the builder with the built-in templates (same parameters as the former 'DefaultAuthPageBuilder').
    /// </summary>
    /// <param name="title">The page title.</param>
    /// <param name="portalUrl">Optional URL of a portal (link is hidden when empty).</param>
    /// <param name="legalUrl">Optional URL of the legal notice (link is hidden when empty).</param>
    /// <param name="logo">Optional URL or 'data:...' of a logo image.</param>
    /// <param name="defaultBgColor">Page background color.</param>
    /// <param name="defaultTextColor">Page text color.</param>
    /// <param name="defaultBgColorDarkmode">Page background color in dark mode.</param>
    /// <param name="defaultTextColorDarkmode">Page text color in dark mode.</param>
    public TemplateAuthPageBuilder(
      string title,
      string portalUrl,
      string legalUrl,
      string logo = null,
      string defaultBgColor = "#7db1c1",
      string defaultTextColor = "#404040",
      string defaultBgColorDarkmode = "#000000",
      string defaultTextColorDarkmode = "#cccccc"
    ) : this(title, portalUrl, legalUrl, null, logo, defaultBgColor, defaultTextColor, defaultBgColorDarkmode, defaultTextColorDarkmode) {
    }

    /// <summary>
    /// Creates the builder with (partially) customized templates.
    /// </summary>
    /// <param name="title">The page title.</param>
    /// <param name="portalUrl">Optional URL of a portal (link is hidden when empty).</param>
    /// <param name="legalUrl">Optional URL of the legal notice (link is hidden when empty).</param>
    /// <param name="templateOverrides">Templates (keyed by template name) replacing the built-in ones (can be null).</param>
    /// <param name="logo">Optional URL or 'data:...' of a logo image.</param>
    /// <param name="defaultBgColor">Page background color.</param>
    /// <param name="defaultTextColor">Page text color.</param>
    /// <param name="defaultBgColorDarkmode">Page background color in dark mode.</param>
    /// <param name="defaultTextColorDarkmode">Page text color in dark mode.</param>
    public TemplateAuthPageBuilder(
      string title,
      string portalUrl,
      string legalUrl,
      IDictionary<string, string> templateOverrides,
      string logo = null,
      string defaultBgColor = "#7db1c1",
      string defaultTextColor = "#404040",
      string defaultBgColorDarkmode = "#000000",
      string defaultTextColorDarkmode = "#cccccc"
    ) {
      _Title = title;
      _Logo = logo;
      _PortalUrl = portalUrl;
      _LegalUrl = legalUrl;
      _DefaultBgColor = defaultBgColor;
      _DefaultTextColor = defaultTextColor;
      _DefaultBgColorDarkmode = defaultBgColorDarkmode;
      _DefaultTextColorDarkmode = defaultTextColorDarkmode;

      IDictionary<string, string> templates = GetDefaultTemplates();
      if (templateOverrides != null) {
        foreach (KeyValuePair<string, string> templateOverride in templateOverrides) {
          templates[templateOverride.Key] = templateOverride.Value;
        }
      }
      _Engine = new TemplateEngine(new MemoryTemplateSource(templates));
    }

    #region " IAuthPageBuilder "

    /// <summary>
    /// Generates the login form (credentials).
    /// </summary>
    public string GetAuthForm(
      string responseType, string prompt, string login_hint, string state, string clientId, string redirectUri,
      string requestedScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      AuthPageModel model = this.CreateModel(viewMode, _Title);
      this.ApplyFormValues(model, responseType, prompt, state, clientId, redirectUri, requestedScopes, viewMode, error);
      model.LoginHint = login_hint;
      return this.Render(LoginTemplateName, model);
    }

    /// <summary>
    /// Generates the login form for an already identified Windows user (pass-through).
    /// </summary>
    public string GetWinAuthForm(
      string responseType, string prompt, string identifiedWinUser, string state, string clientId, string redirectUri,
      string requestedScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      AuthPageModel model = this.CreateModel(viewMode, _Title);
      this.ApplyFormValues(model, responseType, prompt, state, clientId, redirectUri, requestedScopes, viewMode, error);
      model.WinUser = identifiedWinUser;
      return this.Render(PassThroughLoginTemplateName, model);
    }

    /// <summary>
    /// Generates the consent form (scope selection).
    /// </summary>
    public string GetScopeConfirmationForm(
      string responseType, string prompt, string otp, string state, string clientId, string redirectUri,
      string requestedScopes, ScopeDescriptor[] availableScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      AuthPageModel model = this.CreateModel(viewMode, _Title);
      this.ApplyFormValues(model, responseType, prompt, state, clientId, redirectUri, requestedScopes, viewMode, error);
      model.Otp = otp;
      List<ScopeModel> scopes = new List<ScopeModel>();
      if (availableScopes != null) {
        foreach (ScopeDescriptor scope in availableScopes.Where((s) => !s.Invisible)) {
          scopes.Add(new ScopeModel(scope));
        }
      }
      model.Scopes = scopes.ToArray();
      return this.Render(ConsentTemplateName, model);
    }

    /// <summary>
    /// Generates an error page.
    /// </summary>
    public string GetErrorPage(string message, AuthPageViewModeOptions viewMode) {
      AuthPageModel model = this.CreateModel(viewMode, "Error");
      model.Message = message;
      return this.Render(ErrorTemplateName, model);
    }

    /// <summary>
    /// Generates a page displaying the issued access token.
    /// </summary>
    public string GetTokenDisplayPage(TokenIssuingResult tokenResult, AuthPageViewModeOptions viewMode) {
      AuthPageModel model = this.CreateModel(viewMode, _Title);
      model.CardClass = "ath-card ath-wide";
      if (tokenResult != null) {
        model.Token = tokenResult.access_token;
      }
      return this.Render(TokenDisplayTemplateName, model);
    }

    /// <summary>
    /// Embeds a custom body (must include the '&lt;body&gt;' element) into the default page head (incl. CSS).
    /// The placeholders '{{title}}', '{{logo}}', '{{portal_url}}', '{{legal_url}}', '{{bgcolor}}' and
    /// '{{textcolor}}' are still replaced for backward compatibility.
    /// </summary>
    public string GetCustomPage(string customHtmlBodyTemplate, AuthPageViewModeOptions viewMode) {
      AuthPageModel model = this.CreateModel(viewMode, _Title);
      string body = customHtmlBodyTemplate;
      if (body == null) {
        body = string.Empty;
      }
      body = body.Replace("{{title}}", WebUtility.HtmlEncode(_Title));
      if (string.IsNullOrWhiteSpace(_Logo)) {
        body = body.Replace("{{logo}}", string.Empty);
      }
      else {
        body = body.Replace("{{logo}}", "<img class=\"ath-logo\" src=\"" + WebUtility.HtmlEncode(_Logo) + "\" alt=\"\">");
      }
      body = body.Replace("{{portal_url}}", WebUtility.HtmlEncode(_PortalUrl));
      body = body.Replace("{{legal_url}}", WebUtility.HtmlEncode(_LegalUrl));
      body = body.Replace("{{bgcolor}}", model.BgColor);
      body = body.Replace("{{textcolor}}", model.TextColor);
      model.CustomBody = body;
      return this.Render(CustomTemplateName, model);
    }

    #endregion

    #region " Model Creation + Rendering "

    /// <summary>
    /// Renders a template with the specified model (available as '_Page' within the templates).
    /// </summary>
    private string Render(string templateName, AuthPageModel model) {
      TemplateContext context = new TemplateContext();
      context.AddSource("_Page", model);
      return _Engine.Render(templateName, context);
    }

    /// <summary>
    /// Creates a model with all common values (branding, colors, view mode).
    /// </summary>
    private AuthPageModel CreateModel(AuthPageViewModeOptions viewMode, string heading) {
      if (viewMode == null) {
        viewMode = new AuthPageViewModeOptions();
      }
      AuthPageModel model = new AuthPageModel();
      model.Title = _Title;
      model.Heading = heading;
      model.Logo = _Logo;
      model.PortalUrl = _PortalUrl;
      model.LegalUrl = _LegalUrl;
      model.ShowFooter = (!string.IsNullOrWhiteSpace(_PortalUrl) || !string.IsNullOrWhiteSpace(_LegalUrl));
      model.CardClass = "ath-card";
      if (viewMode.LowSpaceEmbedded) {
        model.BodyClass = "ath-embedded";
      }
      else {
        model.BodyClass = "ath-page";
      }

      if (viewMode.Darkmode) {
        model.BgColor = _DefaultBgColorDarkmode;
        model.TextColor = _DefaultTextColorDarkmode;
        model.CardColor = "#1b1d21";
        model.InputColor = "#24272c";
        model.BorderColor = "#3a3f46";
        model.MutedColor = "#9aa3ad";
        model.AccentColor = "#3d93ad";
        model.ErrorBgColor = "#3d1c1f";
        model.ErrorTextColor = "#ff9b9b";
      }
      else {
        model.BgColor = _DefaultBgColor;
        model.TextColor = _DefaultTextColor;
        model.CardColor = "#ffffff";
        model.InputColor = "#ffffff";
        model.BorderColor = "#d5dbe1";
        model.MutedColor = "#6b7480";
        model.AccentColor = "#2f7a92";
        model.ErrorBgColor = "#fdecec";
        model.ErrorTextColor = "#b42318";
      }
      if (!string.IsNullOrWhiteSpace(viewMode.CustomBgColor)) {
        model.BgColor = viewMode.CustomBgColor;
      }
      if (!string.IsNullOrWhiteSpace(viewMode.CustomTextColor)) {
        model.TextColor = viewMode.CustomTextColor;
      }
      return model;
    }

    /// <summary>
    /// Applies the values, which are passed through the html forms.
    /// </summary>
    private void ApplyFormValues(
      AuthPageModel model, string responseType, string prompt, string state, string clientId, string redirectUri,
      string requestedScopes, AuthPageViewModeOptions viewMode, string error
    ) {
      model.ResponseType = responseType;
      model.Prompt = prompt;
      model.State = state;
      model.ClientId = clientId;
      model.RedirectUri = redirectUri;
      model.RequestedScopes = requestedScopes;
      model.Error = error;
      if (viewMode != null && viewMode.LowSpaceEmbedded) {
        model.ViewMode = "2";
      }
      else {
        model.ViewMode = "1";
      }
    }

    #endregion

    #region " Models "

    /// <summary>
    /// The model of a page (available as '_Page' within the templates).
    /// String values are HTML-encoded by the template engine, except 'Prompt', 'Error' and 'CustomBody'
    /// (which are trusted HTML by contract of 'IAuthPageBuilder').
    /// </summary>
    public sealed class AuthPageModel {

      private string _Title;
      private string _Heading;
      private string _Logo;
      private string _PortalUrl;
      private string _LegalUrl;
      private bool _ShowFooter;
      private string _BodyClass;
      private string _CardClass;
      private string _BgColor;
      private string _TextColor;
      private string _CardColor;
      private string _InputColor;
      private string _BorderColor;
      private string _MutedColor;
      private string _AccentColor;
      private string _ErrorBgColor;
      private string _ErrorTextColor;
      private string _ResponseType;
      private string _Prompt;
      private string _State;
      private string _ClientId;
      private string _RedirectUri;
      private string _RequestedScopes;
      private string _ViewMode;
      private string _Error;
      private string _LoginHint;
      private string _WinUser;
      private string _Otp;
      private ScopeModel[] _Scopes = new ScopeModel[0];
      private string _Message;
      private string _Token;
      private string _CustomBody;

      public string Title { get { return _Title; } set { _Title = value; } }
      public string Heading { get { return _Heading; } set { _Heading = value; } }
      public string Logo { get { return _Logo; } set { _Logo = value; } }
      public string PortalUrl { get { return _PortalUrl; } set { _PortalUrl = value; } }
      public string LegalUrl { get { return _LegalUrl; } set { _LegalUrl = value; } }
      public bool ShowFooter { get { return _ShowFooter; } set { _ShowFooter = value; } }
      public string BodyClass { get { return _BodyClass; } set { _BodyClass = value; } }
      public string CardClass { get { return _CardClass; } set { _CardClass = value; } }
      public string BgColor { get { return _BgColor; } set { _BgColor = value; } }
      public string TextColor { get { return _TextColor; } set { _TextColor = value; } }
      public string CardColor { get { return _CardColor; } set { _CardColor = value; } }
      public string InputColor { get { return _InputColor; } set { _InputColor = value; } }
      public string BorderColor { get { return _BorderColor; } set { _BorderColor = value; } }
      public string MutedColor { get { return _MutedColor; } set { _MutedColor = value; } }
      public string AccentColor { get { return _AccentColor; } set { _AccentColor = value; } }
      public string ErrorBgColor { get { return _ErrorBgColor; } set { _ErrorBgColor = value; } }
      public string ErrorTextColor { get { return _ErrorTextColor; } set { _ErrorTextColor = value; } }
      public string ResponseType { get { return _ResponseType; } set { _ResponseType = value; } }
      public string Prompt { get { return _Prompt; } set { _Prompt = value; } }
      public string State { get { return _State; } set { _State = value; } }
      public string ClientId { get { return _ClientId; } set { _ClientId = value; } }
      public string RedirectUri { get { return _RedirectUri; } set { _RedirectUri = value; } }
      public string RequestedScopes { get { return _RequestedScopes; } set { _RequestedScopes = value; } }
      public string ViewMode { get { return _ViewMode; } set { _ViewMode = value; } }
      public string Error { get { return _Error; } set { _Error = value; } }
      public string LoginHint { get { return _LoginHint; } set { _LoginHint = value; } }
      public string WinUser { get { return _WinUser; } set { _WinUser = value; } }
      public string Otp { get { return _Otp; } set { _Otp = value; } }
      public ScopeModel[] Scopes { get { return _Scopes; } set { _Scopes = value; } }
      public bool NoScopes { get { return (_Scopes == null || _Scopes.Length == 0); } }
      public string Message { get { return _Message; } set { _Message = value; } }
      public string Token { get { return _Token; } set { _Token = value; } }
      public string CustomBody { get { return _CustomBody; } set { _CustomBody = value; } }

      /// <summary>
      /// The first letter of the pass-through user (without domain), used as avatar.
      /// </summary>
      public string IdentityInitial {
        get {
          if (string.IsNullOrWhiteSpace(_WinUser)) {
            return "?";
          }
          string name = _WinUser;
          int separatorIndex = name.LastIndexOf('\\');
          if (separatorIndex >= 0 && separatorIndex < name.Length - 1) {
            name = name.Substring(separatorIndex + 1);
          }
          return name.Substring(0, 1).ToUpperInvariant();
        }
      }

    }

    /// <summary>
    /// A (visible) scope within the consent form.
    /// </summary>
    public sealed class ScopeModel {

      private readonly ScopeDescriptor _Descriptor;

      public ScopeModel(ScopeDescriptor descriptor) {
        _Descriptor = descriptor;
      }

      public string Expression { get { return _Descriptor.Expression; } }

      public string Label {
        get {
          if (string.IsNullOrWhiteSpace(_Descriptor.Label)) {
            return _Descriptor.Expression;
          }
          return _Descriptor.Label;
        }
      }

      public bool Selected { get { return _Descriptor.Selected; } }

      public bool ReadOnly { get { return _Descriptor.ReadOnly; } }

      /// <summary>
      /// Disabled fields are not posted, so read-only selected scopes are posted via a hidden field.
      /// </summary>
      public bool PostAsHidden { get { return (_Descriptor.ReadOnly && _Descriptor.Selected); } }

    }

    #endregion

  }

}
