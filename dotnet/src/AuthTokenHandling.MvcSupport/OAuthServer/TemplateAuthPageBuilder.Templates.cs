using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling.OAuth.Server {

  public partial class TemplateAuthPageBuilder {

    /// <summary>
    /// Returns a fresh copy of all built-in templates (keyed by template name).
    /// Use it as starting point for own templates, which can be passed as 'templateOverrides' to the constructor.
    /// </summary>
    public static IDictionary<string, string> GetDefaultTemplates() {
      Dictionary<string, string> templates = new Dictionary<string, string>(StringComparer.Ordinal);
      templates.Add(HeadTemplateName, _HeadTemplate);
      templates.Add(LayoutTemplateName, _LayoutTemplate);
      templates.Add(HiddenFieldsTemplateName, _HiddenFieldsTemplate);
      templates.Add(LoginTemplateName, _LoginTemplate);
      templates.Add(PassThroughLoginTemplateName, _PassThroughLoginTemplate);
      templates.Add(ConsentTemplateName, _ConsentTemplate);
      templates.Add(ErrorTemplateName, _ErrorTemplate);
      templates.Add(TokenDisplayTemplateName, _TokenDisplayTemplate);
      templates.Add(CustomTemplateName, _CustomTemplate);
      return templates;
    }

    #region " Head (incl. CSS) "

    private const string _HeadTemplate = @"<head>
  <meta charset=""utf-8"">
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
  <meta name=""robots"" content=""noindex, nofollow"">
  <title>{{ _Page.Title }}</title>
  <style>
    :root {
      --ath-bg: {{ _Page.BgColor }};
      --ath-text: {{ _Page.TextColor }};
      --ath-card: {{ _Page.CardColor }};
      --ath-input: {{ _Page.InputColor }};
      --ath-border: {{ _Page.BorderColor }};
      --ath-muted: {{ _Page.MutedColor }};
      --ath-accent: {{ _Page.AccentColor }};
      --ath-accent-text: {{ _Page.AccentTextColor }};
      --ath-accent-focus: {{ _Page.AccentFocusColor }};
      --ath-error-bg: {{ _Page.ErrorBgColor }};
      --ath-error-text: {{ _Page.ErrorTextColor }};
      --ath-radius: 10px;
    }

    *, *::before, *::after { box-sizing: border-box; }

    html, body { margin: 0; padding: 0; }

    body {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 18px;
      padding: 32px 16px;
      font: 14px/1.5 system-ui, -apple-system, ""Segoe UI"", Roboto, ""Helvetica Neue"", Arial, sans-serif;
      color: var(--ath-text);
      background: var(--ath-bg);
    }

    .ath-card {
      width: 100%;
      max-width: 380px;
      padding: 28px 28px 24px;
      background: var(--ath-card);
      border: 1px solid var(--ath-border);
      border-radius: var(--ath-radius);
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.18), 0 1px 3px rgba(0, 0, 0, 0.12);
    }

    .ath-card.ath-wide { max-width: 720px; }

    .ath-header { text-align: center; margin-bottom: 18px; }

    .ath-logo { display: block; max-width: 150px; max-height: 80px; margin: 0 auto 12px; }

    .ath-header h1 { margin: 0; font-size: 18px; font-weight: 600; letter-spacing: 0.2px; }

    .ath-prompt { margin: 0 0 16px; color: var(--ath-muted); text-align: center; }

    .ath-form { display: flex; flex-direction: column; gap: 14px; margin: 0; }

    .ath-field { display: flex; flex-direction: column; gap: 6px; font-size: 12px; font-weight: 600; color: var(--ath-muted); }

    .ath-field input {
      width: 100%;
      height: 40px;
      padding: 0 12px;
      font: inherit;
      font-size: 14px;
      font-weight: 400;
      color: var(--ath-text);
      background: var(--ath-input);
      border: 1px solid var(--ath-border);
      border-radius: 8px;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }

    box-shadow: 0 0 0 3px var(--ath-accent-focus); }

    .ath-error {
      padding: 10px 12px;
      color: var(--ath-error-text);
      background: var(--ath-error-bg);
      border-radius: 8px;
      font-weight: 500;
    }

    .ath-error p, .ath-error span { margin: 0; color: inherit !important; }

    .ath-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      width: 100%;
      min-height: 40px;
      padding: 8px 14px;
      font: inherit;
      font-weight: 600;
      text-decoration: none;
      border-radius: 8px;
      border: 1px solid transparent;
      cursor: pointer;
      transition: filter 0.15s ease, background 0.15s ease;
    }

    .ath-btn-primary { color: var(--ath-accent-text); background: var(--ath-accent); }

    .ath-btn-primary:hover { filter: brightness(1.08); }

    .ath-btn-secondary { color: var(--ath-text); background: transparent; border-color: var(--ath-border); }

    .ath-btn-secondary:hover { background: rgba(127, 127, 127, 0.1); }

    .ath-alt { display: flex; flex-direction: column; gap: 10px; margin: 0; }

    .ath-divider { display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--ath-muted); text-transform: uppercase; }

    .ath-divider::before, .ath-divider::after { content: """"; flex: 1; height: 1px; background: var(--ath-border); }

    .ath-identity {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px;
      border: 1px solid var(--ath-border);
      border-radius: 8px;
      background: var(--ath-input);
    }

    .ath-identity-icon {
      flex: none;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--ath-accent-text);
      background: var(--ath-accent);
      font-weight: 700;
    }

    .ath-identity-text { display: flex; flex-direction: column; min-width: 0; }

    .ath-identity-text small { color: var(--ath-muted); }

    .ath-identity-text strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .ath-scopes { list-style: none; margin: 0; padding: 0; border: 1px solid var(--ath-border); border-radius: 8px; overflow: hidden; }

    .ath-scopes li + li { border-top: 1px solid var(--ath-border); }

    .ath-scope { display: flex; align-items: center; gap: 10px; padding: 10px 12px; cursor: pointer; }

    .ath-scope input { width: 16px; height: 16px; margin: 0; accent-color: var(--ath-accent); }

    .ath-scope.ath-readonly { cursor: default; color: var(--ath-muted); }

    .ath-empty { margin: 0; padding: 10px 12px; color: var(--ath-muted); border: 1px dashed var(--ath-border); border-radius: 8px; text-align: center; }

    .ath-token { display: flex; gap: 8px; align-items: stretch; }

    .ath-token textarea {
      flex: 1;
      min-height: 140px;
      padding: 8px;
      font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, ""Liberation Mono"", monospace;
      color: var(--ath-text);
      background: var(--ath-input);
      border: 1px solid var(--ath-border);
      border-radius: 8px;
      resize: vertical;
      word-break: break-all;
    }

    .ath-token .ath-btn { width: auto; min-width: 84px; }

    .ath-footer { display: flex; flex-wrap: wrap; justify-content: center; gap: 6px 18px; font-size: 12px; }

    .ath-footer a { color: var(--ath-text); opacity: 0.85; text-decoration: none; }

    .ath-footer a:hover { opacity: 1; text-decoration: underline; }

    body.ath-embedded { min-height: 0; padding: 8px; background: transparent; justify-content: flex-start; }

    body.ath-embedded .ath-card { max-width: none; box-shadow: none; border: 0; padding: 12px; }

    body.ath-embedded .ath-footer { display: none; }

    @media (max-width: 420px) {
      body { padding: 0; justify-content: flex-start; }
      .ath-card { border-radius: 0; border-left: 0; border-right: 0; }
    }
  </style>
  <style u-if=""_Page.BackgroundImageUrl"">
    body.ath-page {
      background-color: var(--ath-bg);
      background-image: url(""{{ raw _Page.BackgroundImageUrl }}"");
      background-position: center center;
      background-size: cover;
      background-repeat: no-repeat;
      background-attachment: fixed;
    }
  </style>
</head>";

    #endregion

    #region " Layout + Hidden Fields "

    private const string _LayoutTemplate = @"<!DOCTYPE html>
<html lang=""en"">
<u-include template=""Head""></u-include>
<body class=""{{ _Page.BodyClass }}"">
  <main class=""{{ _Page.CardClass }}"">
    <header class=""ath-header"">
      <img u-if=""_Page.Logo"" class=""ath-logo"" src=""{{ _Page.Logo }}"" alt="""">
      <h1>{{ _Page.Heading }}</h1>
    </header>
    <u-slot></u-slot>
  </main>
  <footer class=""ath-footer"" u-if=""_Page.ShowFooter"">
    <a u-if=""_Page.PortalUrl"" rel=""noopener"" target=""_blank"" href=""{{ _Page.PortalUrl }}"">Problems signing in? Open the portal</a>
    <a u-if=""_Page.LegalUrl"" rel=""noopener"" target=""_blank"" href=""{{ _Page.LegalUrl }}"">Legal notice</a>
  </footer>
</body>
</html>";

    private const string _HiddenFieldsTemplate = @"<input type=""hidden"" id=""responseType"" name=""responseType"" value=""{{ _Page.ResponseType }}"">
<input type=""hidden"" id=""state"" name=""state"" value=""{{ _Page.State }}"">
<input type=""hidden"" id=""clientId"" name=""clientId"" value=""{{ _Page.ClientId }}"">
<input type=""hidden"" id=""redirectUri"" name=""redirectUri"" value=""{{ _Page.RedirectUri }}"">
<input type=""hidden"" id=""requestedScopes"" name=""requestedScopes"" value=""{{ _Page.RequestedScopes }}"">
<input type=""hidden"" id=""viewMode"" name=""viewMode"" value=""{{ _Page.ViewMode }}"">";

    #endregion

    #region " Login (Credentials + Pass-Through) "

    private const string _LoginTemplate = @"<u-include template=""Layout"">
  <p class=""ath-prompt"">{{ raw _Page.Prompt }}</p>
  <form class=""ath-form"" method=""post"" action=""./authorize"" enctype=""application/x-www-form-urlencoded"">
    <div class=""ath-error"" u-if=""_Page.Error"">{{ raw _Page.Error }}</div>
    <label class=""ath-field"">Login
      <input type=""text"" name=""login"" value=""{{ _Page.LoginHint }}"" placeholder=""Login"" autocomplete=""username"" autofocus>
    </label>
    <label class=""ath-field"">Password
      <input type=""password"" name=""password"" value="""" placeholder=""Password"" autocomplete=""current-password"">
    </label>
    <u-include template=""HiddenFields""></u-include>
    <button class=""ath-btn ath-btn-primary"" type=""submit"" name=""commit"" value=""Login"">Sign in</button>
  </form>
</u-include>";

    private const string _PassThroughLoginTemplate = @"<u-include template=""Layout"">
  <p class=""ath-prompt"">{{ raw _Page.Prompt }}</p>
  <form class=""ath-form"" method=""post"" action=""./authorize"" enctype=""application/x-www-form-urlencoded"">
    <div class=""ath-error"" u-if=""_Page.Error"">{{ raw _Page.Error }}</div>
    <div class=""ath-identity"">
      <div class=""ath-identity-icon"">{{ _Page.IdentityInitial }}</div>
      <div class=""ath-identity-text"">
        <small>Signed in with your Windows account (pass-through)</small>
        <strong title=""{{ _Page.WinUser }}"">{{ _Page.WinUser }}</strong>
      </div>
    </div>
    <input type=""hidden"" id=""login"" name=""login"" value=""{{ _Page.WinUser }}"">
    <input type=""hidden"" id=""password"" name=""password"" value="""">
    <u-include template=""HiddenFields""></u-include>
    <button class=""ath-btn ath-btn-primary"" type=""submit"" name=""commit"" value=""Proceed"">Continue as {{ _Page.WinUser }}</button>
  </form>
</u-include>";

    #endregion

    #region " Consent "

    private const string _ConsentTemplate = @"<u-include template=""Layout"">
  <p class=""ath-prompt"">{{ raw _Page.Prompt }}</p>
  <form class=""ath-form"" method=""post"" action=""./authorize"" enctype=""application/x-www-form-urlencoded"">
    <div class=""ath-error"" u-if=""_Page.Error"">{{ raw _Page.Error }}</div>
    <ul class=""ath-scopes"" u-if=""_Page.Scopes"">
      <li u-for=""scope in _Page.Scopes"">
        <label class=""ath-scope ath-readonly"" u-if=""scope.ReadOnly"">
          <input type=""checkbox"" id=""scope_{{ scope.Expression }}"" checked disabled u-if=""scope.Selected"">
          <input type=""checkbox"" id=""scope_{{ scope.Expression }}"" disabled u-else>
          <span>{{ scope.Label }}</span>
        </label>
        <label class=""ath-scope"" u-else>
          <input type=""checkbox"" name=""scope_{{ scope.Expression }}"" id=""scope_{{ scope.Expression }}"" checked u-if=""scope.Selected"">
          <input type=""checkbox"" name=""scope_{{ scope.Expression }}"" id=""scope_{{ scope.Expression }}"" u-else>
          <span>{{ scope.Label }}</span>
        </label>
        <input type=""hidden"" name=""scope_{{ scope.Expression }}"" value=""on"" u-if=""scope.PostAsHidden"">
      </li>
    </ul>
    <p class=""ath-empty"" u-if=""_Page.NoScopes"">No additional permissions are requested.</p>
    <input type=""hidden"" id=""otp"" name=""otp"" value=""{{ _Page.Otp }}"">
    <u-include template=""HiddenFields""></u-include>
    <button class=""ath-btn ath-btn-primary"" type=""submit"" name=""commit"" value=""Authorize"">Authorize</button>
  </form>
</u-include>";

    #endregion

    #region " Error + Token Display + Custom "

    private const string _ErrorTemplate = @"<u-include template=""Layout"">
  <div class=""ath-error"">{{ _Page.Message }}</div>
</u-include>";

    private const string _TokenDisplayTemplate = @"<u-include template=""Layout"">
  <p class=""ath-prompt"">Your access token:</p>
  <div class=""ath-token"">
    <textarea id=""ath-token"" readonly aria-label=""Token"">{{ _Page.Token }}</textarea>
    <button class=""ath-btn ath-btn-primary"" type=""button"" onclick=""athCopyToken(this)"">Copy</button>
  </div>
  <script>
    function athCopyToken(button) {
      var field = document.getElementById('ath-token');
      var label = button.textContent;
      field.focus();
      field.select();
      field.setSelectionRange(0, field.value.length);
      var done = function (text) { button.textContent = text; setTimeout(function () { button.textContent = label; }, 1500); };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(field.value).then(function () { done('Copied!'); }, function () { done('Failed'); });
      } else {
        try { document.execCommand('copy'); done('Copied!'); } catch (e) { done('Failed'); }
      }
    }
  </script>
</u-include>";

    private const string _CustomTemplate = @"<!DOCTYPE html>
<html lang=""en"">
<u-include template=""Head""></u-include>
{{ raw _Page.CustomBody }}
</html>";

    #endregion

  }

}
