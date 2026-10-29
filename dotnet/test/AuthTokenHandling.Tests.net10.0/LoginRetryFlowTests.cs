using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security {

  /// <summary>
  /// Tests for the browser based login flow (form roundtrips) of the OAuth2Controller,
  /// especially for retries after a failed login.
  /// </summary>
  [TestClass]
  public class LoginRetryFlowTests {

    private const string _RedirectUri = "https://app.example.com/cb";
    private const string _Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private CheapOAuthOptions _Options;
    private CheapOAuthService _Service;
    private TemplateAuthPageBuilder _PageBuilder;
    private string _ClientId;

    [TestInitialize]
    public void Initialize() {

      _Options = new CheapOAuthOptions();
      _Options.UseFixedAccounts(("demo", "demo", new string[] { "mcp", "admin" }));
      CheapOAuthClientRegistry registry = new CheapOAuthClientRegistry(_Options);
      _Service = new CheapOAuthService(_Options, new CheapOAuthGrantStore(), registry);
      _ClientId = registry.RegisterClient("Test", new string[] { _RedirectUri });
      _PageBuilder = new TemplateAuthPageBuilder("T", null, null);

    }

    /// <summary>
    /// Wrong password, then the correct one: the flow continues to the consent and issues a code
    /// with the original state.
    /// </summary>
    [TestMethod]
    public void WrongPasswordThenCorrectPassword_CodeIssuedWithOriginalState() {

      Dictionary<string, string> form = this.GetForm(this.CreateEntryQuery());
      form["login"] = "demo";
      form["password"] = "WRONG";
      string retryQuery = this.PostAndGetRedirectQuery(form);
      Assert.IsTrue(retryQuery.Contains("err="), "an error message is expected");

      form = this.GetForm(retryQuery);
      Assert.AreEqual("demo", form["login"]);
      Assert.AreEqual(_Challenge, form["codeChallenge"]);
      form["password"] = "demo";
      string consentQuery = this.PostAndGetRedirectQuery(form);
      Assert.IsTrue(consentQuery.Contains("otp="), "a session is expected");

      form = this.GetForm(consentQuery);
      string finalUrl = this.PostAndGetRedirectUrl(form);
      Assert.IsTrue(finalUrl.StartsWith(_RedirectUri + "?code="), finalUrl);
      Assert.IsTrue(finalUrl.EndsWith("&state=abc"), finalUrl);

    }

    /// <summary>
    /// A credential form posted without a password (and without any Windows identity) must not end in a
    /// dead-end error page, but in the login form again (keeping the flow state), so that the user can retry.
    /// </summary>
    [TestMethod]
    public void EmptyPasswordWithoutWindowsIdentity_BackToLoginFormAndRetryable() {

      Dictionary<string, string> form = this.GetForm(this.CreateEntryQuery());
      form["login"] = "demo";
      form["password"] = "";
      string retryQuery = this.PostAndGetRedirectQuery(form);
      Assert.IsTrue(retryQuery.Contains("err="), "an error message is expected");
      Assert.IsFalse(retryQuery.Contains("otp="));

      form = this.GetForm(retryQuery);
      Assert.AreEqual("demo", form["login"]);
      Assert.AreEqual("abc", form["state"]);
      Assert.AreEqual(_Challenge, form["codeChallenge"]);
      form["password"] = "demo";
      string consentQuery = this.PostAndGetRedirectQuery(form);
      Assert.IsTrue(consentQuery.Contains("otp="), "a session is expected");

    }

    #region " Helpers "

    /// <summary>
    /// Creates the query of the initial authorize request.
    /// </summary>
    private string CreateEntryQuery() {
      return (
        "?response_type=code&client_id=" + _ClientId + "&redirect_uri=" + Uri.EscapeDataString(_RedirectUri) +
        "&state=abc&scope=mcp%20admin&code_challenge=" + _Challenge + "&code_challenge_method=S256"
      );
    }

    /// <summary>
    /// Creates a controller with a request context (without any Windows authentication).
    /// </summary>
    private OAuth2Controller CreateController(string rawQuery) {

      ServiceCollection services = new ServiceCollection();
      services.AddLogging();
      services.AddSingleton(_Options);
      services.AddAuthentication();
      services.AddAuthorization();

      DefaultHttpContext httpContext = new DefaultHttpContext();
      httpContext.RequestServices = services.BuildServiceProvider();
      httpContext.Request.Scheme = "https";
      httpContext.Request.Host = new HostString("localhost");
      httpContext.Request.Path = "/oauth2/authorize";
      httpContext.Request.QueryString = new QueryString(rawQuery);

      OAuth2Controller controller = new OAuth2Controller(NullLogger<OAuth2Controller>.Instance, _Service, _PageBuilder);
      controller.ControllerContext = new ControllerContext();
      controller.ControllerContext.HttpContext = httpContext;
      return controller;
    }

    /// <summary>
    /// Simulates the browser: GET authorize and returns the fields, which would be posted by the rendered form.
    /// </summary>
    private Dictionary<string, string> GetForm(string rawQuery) {

      rawQuery = rawQuery.Replace(" ", "%20");
      Dictionary<string, StringValues> query = QueryHelpers.ParseQuery(rawQuery);
      Func<string, string> getParam = (name) => {
        if (query.ContainsKey(name)) {
          return query[name].ToString();
        }
        return null;
      };

      int viewMode = 0;
      int.TryParse(getParam("view_mode"), out viewMode);

      OAuth2Controller controller = this.CreateController(rawQuery);
      ActionResult result = controller.GetLogonPage(
        getParam("response_type"), getParam("client_id"), getParam("redirect_uri"), getParam("state"), getParam("scope"),
        getParam("login_hint"), getParam("err"), getParam("otp"), viewMode, getParam("code"),
        getParam("code_challenge"), getParam("code_challenge_method"), getParam("resource"), getParam("prompt")
      );
      Assert.IsInstanceOfType(result, typeof(ContentResult));

      return ParseFormFields(((ContentResult)result).Content);
    }

    /// <summary>
    /// Posts the form and returns the url of the expected redirect.
    /// </summary>
    private string PostAndGetRedirectUrl(Dictionary<string, string> form) {

      Dictionary<string, StringValues> fields = new Dictionary<string, StringValues>();
      foreach (KeyValuePair<string, string> field in form) {
        fields[field.Key] = field.Value;
      }

      OAuth2Controller controller = this.CreateController("");
      ActionResult result = controller.PostLogonForm(new FormCollection(fields));
      Assert.IsInstanceOfType(result, typeof(RedirectResult));

      return ((RedirectResult)result).Url;
    }

    /// <summary>
    /// Posts the form and returns the query of the expected (internal) redirect.
    /// </summary>
    private string PostAndGetRedirectQuery(Dictionary<string, string> form) {
      string url = this.PostAndGetRedirectUrl(form);
      Assert.IsTrue(url.StartsWith("./authorize?"), url);
      return url.Substring(url.IndexOf('?'));
    }

    /// <summary>
    /// Extracts the fields, which a browser would post (checked checkboxes only).
    /// </summary>
    private static Dictionary<string, string> ParseFormFields(string html) {

      Dictionary<string, string> result = new Dictionary<string, string>();

      foreach (Match inputMatch in Regex.Matches(html, "<input([^>]*)>")) {
        string attributes = inputMatch.Groups[1].Value;
        Match nameMatch = Regex.Match(attributes, "name=\"([^\"]*)\"");
        if (!nameMatch.Success) {
          continue;
        }

        string value = "";
        Match valueMatch = Regex.Match(attributes, "value=\"([^\"]*)\"");
        if (valueMatch.Success) {
          value = WebUtility.HtmlDecode(valueMatch.Groups[1].Value);
        }

        if (attributes.Contains("checkbox")) {
          if (!attributes.Contains("checked")) {
            continue;
          }
          value = "on";
        }

        result[nameMatch.Groups[1].Value] = value;
      }

      return result;
    }

    #endregion

  }

}
