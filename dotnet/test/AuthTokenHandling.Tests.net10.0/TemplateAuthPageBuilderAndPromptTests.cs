using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security {

  /// <summary>
  /// Tests for the template based auth pages, the 'prompt' param support and the consent skipping.
  /// </summary>
  [TestClass]
  public class TemplateAuthPageBuilderAndPromptTests {

    #region " TemplateAuthPageBuilder "

    /// <summary>
    /// The login form contains all fields required by the form-POST and encodes untrusted values.
    /// </summary>
    [TestMethod]
    public void GetAuthForm_DefaultTemplates_RendersFormWithEncodedValues() {
      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("My Title", "https://portal", null);

      string html = builder.GetAuthForm(
        "code", "Please enter your credentials:", "<script>", "st\"ate", "client1", "https://app/cb", "a b",
        new AuthPageViewModeOptions(), ""
      );

      Assert.IsTrue(html.Contains("</form>"));
      Assert.IsTrue(html.Contains("name=\"login\""));
      Assert.IsTrue(html.Contains("name=\"password\""));
      Assert.IsTrue(html.Contains("name=\"clientId\" value=\"client1\""));
      Assert.IsTrue(html.Contains("name=\"viewMode\" value=\"1\""));
      Assert.IsTrue(html.Contains("https://portal"));
      Assert.IsFalse(html.Contains("value=\"<script>\""), "login hint must be encoded");
      Assert.IsFalse(html.Contains("st\"ate"), "state must be encoded");
      Assert.IsTrue(html.Contains("#7db1c1"), "the background color must be rendered into the css");
    }

    /// <summary>
    /// The pass-through form displays the identified user and posts an empty password.
    /// </summary>
    [TestMethod]
    public void GetWinAuthForm_DefaultTemplates_RendersIdentity() {
      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("T", null, null);

      string html = builder.GetWinAuthForm(
        "code", "Confirm", "DOMAIN\\jdoe", "s", "c", "https://app/cb", "", new AuthPageViewModeOptions(), ""
      );

      Assert.IsTrue(html.Contains("DOMAIN\\jdoe"));
      Assert.IsTrue(html.Contains(">J<"), "the initial of the user (without domain) is expected");
      Assert.IsTrue(html.Contains("name=\"password\" value=\"\""));
      Assert.IsTrue(html.Contains("</form>"));
    }

    /// <summary>
    /// The consent form lists visible scopes only and posts read-only selected scopes as hidden fields.
    /// </summary>
    [TestMethod]
    public void GetScopeConfirmationForm_VariousScopes_RendersVisibleScopesOnly() {
      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("T", null, null);
      ScopeDescriptor[] scopes = new ScopeDescriptor[] {
        new ScopeDescriptor { Expression = "read", Label = "Read access", Selected = true },
        new ScopeDescriptor { Expression = "fixed", Label = "Fixed", Selected = true, ReadOnly = true },
        new ScopeDescriptor { Expression = "hidden", Label = "Hidden", Invisible = true }
      };

      string html = builder.GetScopeConfirmationForm(
        "code", "Select", "otp1", "s", "c", "https://app/cb", "read", scopes, new AuthPageViewModeOptions { LowSpaceEmbedded = true }, ""
      );

      Assert.IsTrue(html.Contains("name=\"scope_read\""));
      Assert.IsTrue(html.Contains("Read access"));
      Assert.IsTrue(html.Contains("name=\"scope_fixed\" value=\"on\""));
      Assert.IsFalse(html.Contains("scope_hidden"));
      Assert.IsTrue(html.Contains("name=\"otp\" value=\"otp1\""));
      Assert.IsTrue(html.Contains("ath-embedded"));
      Assert.IsTrue(html.Contains("name=\"viewMode\" value=\"2\""));
    }

    /// <summary>
    /// Error page, token display and custom page are rendered.
    /// </summary>
    [TestMethod]
    public void OtherPages_DefaultTemplates_Rendered() {
      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("T", null, null);
      AuthPageViewModeOptions options = new AuthPageViewModeOptions { Darkmode = true };

      string errorPage = builder.GetErrorPage("Something <b>failed</b>", options);
      Assert.IsTrue(errorPage.Contains("Something &lt;b&gt;failed&lt;/b&gt;"));
      Assert.IsTrue(errorPage.Contains("#000000"), "dark mode background expected");

      TokenIssuingResult token = new TokenIssuingResult();
      token.access_token = "abc.def.ghi";
      string tokenPage = builder.GetTokenDisplayPage(token, options);
      Assert.IsTrue(tokenPage.Contains("abc.def.ghi"));

      string customPage = builder.GetCustomPage("<body><h1>{{title}}</h1></body>", options);
      Assert.IsTrue(customPage.Contains("<h1>T</h1>"));
      Assert.IsTrue(customPage.Contains("<style>"));
    }

    /// <summary>
    /// Single templates can be replaced, the others are kept.
    /// </summary>
    [TestMethod]
    public void TemplateOverrides_ErrorTemplateReplaced_UsesOverride() {
      Dictionary<string, string> overrides = new Dictionary<string, string>();
      overrides.Add(TemplateAuthPageBuilder.ErrorTemplateName, "<div class=\"custom\">{{ _Page.Message }}</div>");
      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("T", null, null, overrides);

      Assert.AreEqual("<div class=\"custom\">oops</div>", builder.GetErrorPage("oops", new AuthPageViewModeOptions()));
      Assert.IsTrue(builder.GetAuthForm("code", "p", "", "", "c", "r", "", new AuthPageViewModeOptions(), "").Contains("</form>"));
      Assert.AreEqual(9, TemplateAuthPageBuilder.GetDefaultTemplates().Count);
    }

    #endregion

    #region " Prompt + Consent Skipping "

    /// <summary>
    /// Verifies the evaluation and validation of the 'prompt' param.
    /// </summary>
    [TestMethod]
    public void PromptHelpers_VariousInputs_EvaluatedCorrectly() {
      Assert.IsTrue(OAuth2Controller.HasPromptValue("login CONSENT", "consent"));
      Assert.IsFalse(OAuth2Controller.HasPromptValue(null, "none"));
      Assert.IsFalse(OAuth2Controller.HasPromptValue("nonex", "none"));

      string error;
      Assert.IsTrue(OAuth2Controller.TryValidatePromptParam(null, out error));
      Assert.IsTrue(OAuth2Controller.TryValidatePromptParam("none", out error));
      Assert.IsTrue(OAuth2Controller.TryValidatePromptParam("login consent", out error));
      Assert.IsTrue(OAuth2Controller.TryValidatePromptParam("unknown", out error), "unknown values are tolerated");
      Assert.IsFalse(OAuth2Controller.TryValidatePromptParam("none consent", out error));
      Assert.IsNotNull(error);
    }

    /// <summary>
    /// Verifies that the prompt is passed through forms and authorize-redirects.
    /// </summary>
    [TestMethod]
    public void PromptRoundtrip_FormAndQuery_Preserved() {
      string html = "<form></form>";
      Assert.IsTrue(OAuth2Controller.TryInjectPromptFormField(ref html, "consent"));
      Assert.IsTrue(html.Contains("name=\"oauthPrompt\" value=\"consent\""));

      string unchanged = "<body></body>";
      Assert.IsTrue(OAuth2Controller.TryInjectPromptFormField(ref unchanged, null));
      Assert.IsFalse(OAuth2Controller.TryInjectPromptFormField(ref unchanged, "consent"));

      string url = "./authorize?client_id=abc";
      Assert.AreEqual(url, OAuth2Controller.AppendRoundtripQueryParams(url, null, null, null));
      Assert.IsTrue(OAuth2Controller.AppendRoundtripQueryParams(url, null, null, "consent").EndsWith("&prompt=consent"));
    }

    /// <summary>
    /// The consent step can only be skipped, if there is nothing to select.
    /// </summary>
    [TestMethod]
    public void TryGetScopesWithoutSelection_VariousScopes_EvaluatedCorrectly() {
      string[] scopes;

      Assert.IsTrue(OAuth2Controller.TryGetScopesWithoutSelection(null, out scopes));
      Assert.AreEqual(0, scopes.Length);

      Assert.IsTrue(OAuth2Controller.TryGetScopesWithoutSelection(new ScopeDescriptor[0], out scopes));
      Assert.AreEqual(0, scopes.Length);

      ScopeDescriptor[] onlyFixed = new ScopeDescriptor[] {
        new ScopeDescriptor { Expression = "fixed", Selected = true, ReadOnly = true },
        new ScopeDescriptor { Expression = "off", Selected = false, ReadOnly = true },
        new ScopeDescriptor { Expression = "hidden", Selected = false, Invisible = true }
      };
      Assert.IsTrue(OAuth2Controller.TryGetScopesWithoutSelection(onlyFixed, out scopes));
      CollectionAssert.AreEqual(new string[] { "fixed" }, scopes);

      ScopeDescriptor[] selectable = new ScopeDescriptor[] {
        new ScopeDescriptor { Expression = "read", Selected = true }
      };
      Assert.IsFalse(OAuth2Controller.TryGetScopesWithoutSelection(selectable, out scopes));
    }

    #endregion

  }

}
