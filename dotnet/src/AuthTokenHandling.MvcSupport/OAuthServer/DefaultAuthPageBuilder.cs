using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static System.Net.WebRequestMethods;

namespace Security.AccessTokenHandling.OAuthServer {

  public class DefaultAuthPageBuilder : IAuthPageBuilder {

    // WHY THE HELL AREN'T WE USING EMBEDDED RES-FILES HERE?
    // >> WERE BUILDING A MULTI-TARGET-LIB AND THERE ARE ACTUALLY SOME
    // PROBLEMS WITH EMBEDDED FILES - SO THIS IS TEMPORARY (MID_TERM)

    /// <summary>
    /// 
    /// </summary>
    /// <param name="title"></param>
    /// <param name="logo">URL or 'DATA:...'</param>
    /// <param name="portalUrl"></param>
    /// <param name="legalUrl"></param>
    /// <param name="bgColor"></param>
    /// <param name="textColor"></param>
    public DefaultAuthPageBuilder(
      string title,
      string portalUrl,
      string legalUrl,
      string logo = null,
      string bgColor = "#0ca3d2",
      string textColor= "#404040"
      ) {
      _Title = title;
      _Logo = logo;
      _PortalUrl = portalUrl;
      _LegalUrl = legalUrl;
      _BgColor = bgColor;
      _TextColor = textColor;
    }

    private readonly string _Title;
    private readonly string _Logo;
    private readonly string _PortalUrl;
    private readonly string _LegalUrl;
    private readonly string _BgColor;
    private readonly string _TextColor;

    private void ReplaceCommonPlaceholders(StringBuilder sb) {
      sb.Replace("{{title}}", _Title);
      if (string.IsNullOrWhiteSpace(_Logo)) {
        sb.Replace("{{logo}}", "");
      }
      else {
        sb.Replace("{{logo}}", $"<div align=\"center\"><img src=\"{_Logo}\" width=\"150\" /></div>");
      }
      sb.Replace("{{portal_url}}", _PortalUrl);
      sb.Replace("{{legal_url}}", _LegalUrl);
      sb.Replace("{{bgcolor}}", _BgColor);
      sb.Replace("{{textcolor}}", _TextColor);
    }

    #region " HTML Base Template "

    public string GetCustomPage(string customHtmlBodyTemplate) {
      var sb = new StringBuilder(8000);
      sb.Append(_HtmlBaseTemplateWithCSS);
      sb.Replace("<body />", customHtmlBodyTemplate);
      this.ReplaceCommonPlaceholders(sb);
      return sb.ToString();
    }

    private readonly string _HtmlBaseTemplateWithCSS = (
@"
<!DOCTYPE html>
<html>
  <head>
    <title>{{title}}</title>
    <style>

      body {
        font: 13px/20px ""Lucida Grande"", Tahoma, Verdana, sans-serif;
        color: {{textcolor}};
        background: {{bgcolor}};
      }

      .login {
        position: relative;
        margin: 30px auto;
        padding: 20px 20px 20px;
        width: 310px;
        background: white;
        border-radius: 3px;
        -webkit-box-shadow: 0 0 200px rgba(255, 255, 255, 0.5), 0 1px 2px rgba(0, 0, 0, 0.3);
        box-shadow: 0 0 200px rgba(255, 255, 255, 0.5), 0 1px 2px rgba(0, 0, 0, 0.3);
      }

      .login:before {
        content: '';
        position: absolute;
        top: -8px;
        right: -8px;
        bottom: -8px;
        left: -8px;
        z-index: -1;
        background: rgba(0, 0, 0, 0.08);
        border-radius: 4px;
      }

      .login h1 {
        margin: -20px -20px 21px;
        line-height: 40px;
        font-size: 15px;
        font-weight: bold;
        color: #555;
        text-align: center;
        text-shadow: 0 1px white;
        background: #f3f3f3;
        border-bottom: 1px solid #cfcfcf;
        border-radius: 3px 3px 0 0;
        background-image: -webkit-linear-gradient(top, whiteffd, #eef2f5);
        background-image: -moz-linear-gradient(top, whiteffd, #eef2f5);
        background-image: -o-linear-gradient(top, whiteffd, #eef2f5);
        background-image: linear-gradient(to bottom, whiteffd, #eef2f5);
        -webkit-box-shadow: 0 1px whitesmoke;
        box-shadow: 0 1px whitesmoke;
      }

      .login p {
        margin: 20px 0 0;
      }

      .login p:first-child {
        margin-top: 0;
      }

      .login input[type=text], .login input[type=password] {
        width: 278px;
      }

      .login p.scopeselect {
        /* float: left;
           line-height: 31px;*/
      }

        .login p.scopeselect label {
          font-size: 12px;
          color: #777;
          cursor: pointer;
        }

        .login p.scopeselect input {
          position: relative;
          bottom: 1px;
          margin-right: 4px;
          vertical-align: middle;
        }

      .login p.submit {
        text-align: right;
      }

      .login-help {
        margin: 20px 0;
        font-size: 11px;
        color: white;
        text-align: center;
        text-shadow: 0 1px #2a85a1;
      }

      .login-help a {
        color: #cce7fa;
        text-decoration: none;
      }

      .login-help a:hover {
        text-decoration: underline;
      }

      :-moz-placeholder {
        color: #c9c9c9 !important;
        font-size: 13px;
      }

      ::-webkit-input-placeholder {
        color: #ccc;
        font-size: 13px;
      }

      input {
        font-family: 'Lucida Grande', Tahoma, Verdana, sans-serif;
        font-size: 14px;
      }

      input[type=text], input[type=password] {
        margin: 5px;
        padding: 0 10px;
        width: 200px;
        height: 34px;
        color: #404040;
        background: white;
        border: 1px solid;
        border-color: #c4c4c4 #d1d1d1 #d4d4d4;
        border-radius: 2px;
        outline: 5px solid #eff4f7;
        -moz-outline-radius: 3px;
        -webkit-box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.12);
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.12);
      }

      input[type=text]:focus, input[type=password]:focus {
        border-color: #7dc9e2;
        outline-color: #dceefc;
        outline-offset: 0;
      }

      input[type=submit] {
        padding: 0 18px;
        height: 29px;
        font-size: 12px;
        font-weight: bold;
        color: #527881;
        text-shadow: 0 1px #e3f1f1;
        background: #cde5ef;
        border: 1px solid;
        border-color: #b4ccce #b3c0c8 #9eb9c2;
        border-radius: 16px;
        outline: 0;
        -webkit-box-sizing: content-box;
        -moz-box-sizing: content-box;
        box-sizing: content-box;
        background-image: -webkit-linear-gradient(top, #edf5f8, #cde5ef);
        background-image: -moz-linear-gradient(top, #edf5f8, #cde5ef);
        background-image: -o-linear-gradient(top, #edf5f8, #cde5ef);
        background-image: linear-gradient(to bottom, #edf5f8, #cde5ef);
        -webkit-box-shadow: inset 0 1px white, 0 1px 2px rgba(0, 0, 0, 0.15);
        box-shadow: inset 0 1px white, 0 1px 2px rgba(0, 0, 0, 0.15);
      }

      input[type=submit]:active {
        background: #cde5ef;
        border-color: #9eb9c2 #b3c0c8 #b4ccce;
        -webkit-box-shadow: inset 0 0 3px rgba(0, 0, 0, 0.2);
        box-shadow: inset 0 0 3px rgba(0, 0, 0, 0.2);
      }

      .lt-ie9 input[type=text], .lt-ie9 input[type=password] {
        line-height: 34px;
      }

    </style>
  </head>
  <body />
</html>
");

    #endregion

    #region " Auth Form "

    /// <summary>
    /// Generates the HTML LOGON Form
    /// </summary>
    /// <param name="prompt"></param>
    /// <param name="login_hint"></param>
    /// <param name="state"></param>
    /// <param name="clientId"></param>
    /// <param name="redirectUri"></param>
    /// <param name="requestedScopes"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <param name="error"></param>
    /// <returns></returns>
    public string GetAuthForm(
      string prompt, string login_hint, string state, string clientId, string redirectUri, string requestedScopes, int viewMode, string error
    ) {
      var sb = new StringBuilder(8000);
      sb.Append(_HtmlBaseTemplateWithCSS);
      if(viewMode == 2) {
        sb.Replace("<body />", _AuthFormTemplateEmbedded);
      }
      else {
        sb.Replace("<body />", _AuthFormTemplate);
      }
      this.ReplaceCommonPlaceholders(sb);
      sb.Replace("{{prompt}}", prompt);
      sb.Replace("{{login_hint}}", login_hint);
      sb.Replace("{{state}}", state);
      sb.Replace("{{clientId}}", clientId);
      sb.Replace("{{redirectUri}}", redirectUri);
      sb.Replace("{{requestedScopes}}", requestedScopes);
      sb.Replace("{{viewMode}}", viewMode.ToString());
      sb.Replace("{{error}}", error);
      return sb.ToString();
    }

    private readonly string _AuthFormTemplate = (
@"  <body>
    <div class=""login"">
      <h1>{{title}}</h1>
      <form method=""post"" action=""./oauth/authorize"" enctype=""application/x-www-form-urlencoded"">
        {{logo}}
        <p>{{prompt}}</p>
        <p><input type=""text"" name=""login"" value=""{{login_hint}}"" placeholder=""Login""></p>
        <p><input type=""password"" name=""password"" value="""" placeholder=""Password""></p>
        {{error}}
        <input type=""hidden"" id=""state"" name=""state"" value=""{{state}}"">
        <input type=""hidden"" id=""clientId"" name=""clientId"" value=""{{clientId}}"">
        <input type=""hidden"" id=""redirectUri"" name=""redirectUri"" value=""{{redirectUri}}"">
        <input type=""hidden"" id=""requestedScopes"" name=""requestedScopes"" value=""{{requestedScopes}}"">
        <input type=""hidden"" id=""viewMode"" name=""viewMode"" value=""{{viewMode}}"">
        <p class=""submit""><input type=""submit"" name=""commit"" value=""Login""></p>
      </form>
    </div>
    <div class=""login-help"">
      <p>Problems with your password?<br /><a rel=""noopener"" target=""_blank"" href=""{{portal_url}}"">Click here to go to the portal</a></p><br />
      <br />
      <br />
      <p><a rel=""noopener"" target=""_blank"" href=""{{legal_url}}"">Impressum</a></p>
    </div>
  </body>");

    private readonly string _AuthFormTemplateEmbedded = (
@"  <body>
    <div class=""login"">
      <h1>{{title}}</h1>
      <form method=""post"" action=""./oauth/authorize"" enctype=""application/x-www-form-urlencoded"">
        {{logo}}
        <p>{{prompt}}</p>
        <p><input type=""text"" name=""login"" value=""{{login_hint}}"" placeholder=""Login""></p>
        <p><input type=""password"" name=""password"" value="""" placeholder=""Password""></p>
        {{error}}
        <input type=""hidden"" id=""state"" name=""state"" value=""{{state}}"">
        <input type=""hidden"" id=""clientId"" name=""clientId"" value=""{{clientId}}"">
        <input type=""hidden"" id=""redirectUri"" name=""redirectUri"" value=""{{redirectUri}}"">
        <input type=""hidden"" id=""requestedScopes"" name=""requestedScopes"" value=""{{requestedScopes}}"">
        <input type=""hidden"" id=""viewMode"" name=""viewMode"" value=""{{viewMode}}"">
        <p class=""submit""><input type=""submit"" name=""commit"" value=""Login""></p>
      </form>
    </div>
  </body>");

    #endregion

    #region " Scope Confirmation Form "

    /// <summary>
    /// Generates the HTML SCOPE SELECTION Form (Step 2)
    /// </summary>
    /// <param name="prompt"></param>
    /// <param name="otp"></param>
    /// <param name="state"></param>
    /// <param name="clientId"></param>
    /// <param name="redirectUri"></param>
    /// <param name="requestedScopes"></param>
    /// <param name="availableScopes"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <param name="error"></param>
    /// <returns></returns>
    public string GetScopeConfirmationForm(
      string prompt, string otp, string state, string clientId, string redirectUri, 
      string requestedScopes, ScopeDescriptor[] availableScopes, int viewMode, string error
    ) {
      var sb = new StringBuilder(8000);
      sb.Append(_HtmlBaseTemplateWithCSS);
      if (viewMode == 2) {
        sb.Replace("<body />", _ScopeConfirmationTemplateEmbedded);
      }
      else {
        sb.Replace("<body />", _ScopeConfirmationTemplate);
      }
      this.ReplaceCommonPlaceholders(sb);
      sb.Replace("{{prompt}}", prompt);
      sb.Replace("{{otp}}", otp);
      sb.Replace("{{state}}", state);
      sb.Replace("{{clientId}}", clientId);
      sb.Replace("{{redirectUri}}", redirectUri);
      sb.Replace("{{requestedScopes}}", requestedScopes);
      sb.Replace("{{viewMode}}", viewMode.ToString());
      sb.Replace("{{error}}", error);

      var scopeChecks = new StringBuilder();
      foreach (var availableScope in availableScopes.Where((s) => !s.Invisible)) {
        var line = _ScopeTemplate;
        if (availableScope.Selected) {
          line = line.Replace("{{checked}}", " checked=\"checked\"");
        }
        else {
          line = line.Replace("{{checked}}", "");
        }
        if (availableScope.ReadOnly) {
          line = line.Replace("{{readonly}}", " disabled=\"disabled\"");
        }
        else {
          line = line.Replace("{{readonly}}", "");
        }
        line = line.Replace("{{label}}", availableScope.Label);
        line = line.Replace("{{expr}}", availableScope.Expression);
        scopeChecks.AppendLine(line);
      }
      sb.Replace("{{scope_checks}}", scopeChecks.ToString());

      return sb.ToString();
    }

    private readonly string _ScopeTemplate = "          <label><input type=\"checkbox\" name=\"scope_{{expr}}\" id=\"scope_{{expr}}\"{{checked}}{{readonly}} > {{label}} </label><br />";

    private readonly string _ScopeConfirmationTemplate = (
@"  <body>
    <div class=""login"">
      <h1>{{title}}</h1>
      <form method=""post"" action=""./oauth/authorize"" enctype=""application/x-www-form-urlencoded"">
        {{logo}}
        <p>{{prompt}}</p>
        {{error}}
        <input type=""hidden"" id=""state"" name=""state"" value=""{{state}}"">
        <input type=""hidden"" id=""otp"" name=""otp"" value=""{{otp}}"">
        <input type=""hidden"" id=""clientId"" name=""clientId"" value=""{{clientId}}"">
        <input type=""hidden"" id=""redirectUri"" name=""redirectUri"" value=""{{redirectUri}}"">
        <input type=""hidden"" id=""requestedScopes"" name=""requestedScopes"" value=""{{requestedScopes}}"">
        <p class=""scopeselect"">
          {{scope_checks}}
        </p>
        <p class=""submit""><input type=""submit"" name=""commit"" value=""Authorize!""></p>
      </form>
    </div>
    <div class=""login-help"">
      <p>Problems with your password?<br /><a rel=""noopener"" target=""_blank"" href=""{{portal_url}}"">Click here to go to the portal</a></p><br />
      <br />
      <br />
      <p><a rel=""noopener"" target=""_blank"" href=""{{legal_url}}"">Impressum</a></p>
    </div>
  </body>");

    private readonly string _ScopeConfirmationTemplateEmbedded = (
@"  <body>
    <div class=""login"">
      <h1>{{title}}</h1>
      <form method=""post"" action=""./oauth/authorize"" enctype=""application/x-www-form-urlencoded"">
        {{logo}}
        <p>{{prompt}}</p>
        {{error}}
        <input type=""hidden"" id=""state"" name=""state"" value=""{{state}}"">
        <input type=""hidden"" id=""otp"" name=""otp"" value=""{{otp}}"">
        <input type=""hidden"" id=""clientId"" name=""clientId"" value=""{{clientId}}"">
        <input type=""hidden"" id=""redirectUri"" name=""redirectUri"" value=""{{redirectUri}}"">
        <input type=""hidden"" id=""requestedScopes"" name=""requestedScopes"" value=""{{requestedScopes}}"">
        <p class=""scopeselect"">
          {{scope_checks}}
        </p>
        <p class=""submit""><input type=""submit"" name=""commit"" value=""Authorize!""></p>
      </form>
    </div>
  </body>");

    #endregion

    #region " Error Page "

    /// <summary>
    /// Generates a HTML ERROR PAGE
    /// </summary>
    /// <param name="message"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <returns></returns>
    public string GetErrorPage(string message, int viewMode) {
      var sb = new StringBuilder(8000);
      sb.Append(_HtmlBaseTemplateWithCSS);
      if (viewMode == 2) {
        sb.Replace("<body />", _GetErrorPageTemplateEmbedded);
      }
      else {
        sb.Replace("<body />", _GetErrorPageTemplate);
      }
      this.ReplaceCommonPlaceholders(sb);
      sb.Replace("{{message}}", message);
      return sb.ToString();
    }

    private readonly string _GetErrorPageTemplate = (
@"  <body>
    <div class=""login"">
      <h1>Error</h1>
      <p><span style=""color:red""><b>{{message}}</b></span></p>
    </div>
    <div class=""login-help"">
      <p>Problems with your password?<br /><a rel=""noopener"" target=""_blank"" href=""{{portal_url}}"">Click here to go to the portal</a></p><br />
      <br />
      <br />
      <p><a rel=""noopener"" target=""_blank"" href=""{{legal_url}}"">Impressum</a></p>
    </div>
  </body>");

    private readonly string _GetErrorPageTemplateEmbedded = (
@"  <body>
    <div class=""login"">
      <h1>Error</h1>
      <p><span style=""color:red""><b>{{message}}</b></span></p>
    </div>
  </body>");

    #endregion

  }

}
