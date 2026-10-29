using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.AccessTokenHandling.OAuth.Server;

namespace Security {

  /// <summary>
  /// Tests for the (optionally CI-color transformed) background image of the template based auth pages.
  /// </summary>
  [TestClass]
  public class TemplateAuthPageBuilderBackgroundTests {

    /// <summary>
    /// By default the embedded image is referenced as zoomed ('cover') background.
    /// </summary>
    [TestMethod]
    public void GetAuthForm_Default_RendersEmbeddedZoomedBackground() {

      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);

      string html = builder.GetAuthForm("code", "", "", "", "c", "https://app/cb", "", new AuthPageViewModeOptions(), "");

      Assert.IsTrue(html.Contains("url(\"./background.png\")"));
      Assert.IsTrue(html.Contains("background-size: cover"));
    }

    /// <summary>
    /// The embedded mode for iframes and a disabled background do not render any background image.
    /// </summary>
    [TestMethod]
    public void GetAuthForm_EmbeddedOrDisabled_RendersNoBackground() {

      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);
      AuthPageViewModeOptions embedded = new AuthPageViewModeOptions();
      embedded.LowSpaceEmbedded = true;

      string embeddedHtml = builder.GetAuthForm("code", "", "", "", "c", "https://app/cb", "", embedded, "");
      Assert.IsFalse(embeddedHtml.Contains("background.png"));

      builder.ShowBackgroundImage = false;
      string disabledHtml = builder.GetAuthForm("code", "", "", "", "c", "https://app/cb", "", new AuthPageViewModeOptions(), "");
      Assert.IsFalse(disabledHtml.Contains("background.png"));
    }

    /// <summary>
    /// A custom background image url replaces the embedded image and is css-escaped.
    /// </summary>
    [TestMethod]
    public void GetErrorPage_CustomBackgroundImageUrl_IsRenderedEscaped() {

      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);
      builder.CustomBackgroundImageUrl = "https://cdn/bg.png\");}</style><script>";

      string html = builder.GetErrorPage("err", new AuthPageViewModeOptions());

      Assert.IsTrue(html.Contains("url(\"https://cdn/bg.png%22%29;}%3C/style%3E%3Cscript%3E\")"));
      Assert.IsFalse(html.Contains("</style><script>"));
    }

    /// <summary>
    /// The original embedded image is available and a valid PNG.
    /// </summary>
    [TestMethod]
    public void GetBackgroundImagePng_Original_ReturnsEmbeddedPng() {

      byte[] png = TemplateAuthPageBuilder.GetBackgroundImagePng(null);

      Assert.IsNotNull(png);
      Assert.AreEqual(137, png[0]);
      Assert.AreEqual((byte)'P', png[1]);
    }

    /// <summary>
    /// A configured CI color is referenced by the page, transformed, cached and (for a neutral color) free of any blue.
    /// </summary>
    [TestMethod]
    public void GetBackgroundImagePng_ConfiguredGray_RemovesBlueAndIsCached() {

      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);
      builder.BackgroundCiColor = "#333";

      string html = builder.GetAuthForm("code", "", "", "", "c", "https://app/cb", "", new AuthPageViewModeOptions(), "");
      Assert.IsTrue(html.Contains("url(\"./background.png?ci=333333\")"));

      byte[] first = TemplateAuthPageBuilder.GetBackgroundImagePng("333333");
      byte[] second = TemplateAuthPageBuilder.GetBackgroundImagePng("#333333");

      Assert.IsNotNull(first);
      Assert.AreSame(first, second, "the transformed image must be cached");

      PngPixels pixels = PngImageCodec.Decode(first);
      for (int i = 0; i < pixels.Pixels.Length; i += pixels.BytesPerPixel * 997) {
        Assert.AreEqual(pixels.Pixels[i], pixels.Pixels[i + 1]);
        Assert.AreEqual(pixels.Pixels[i + 1], pixels.Pixels[i + 2]);
      }
    }

    /// <summary>
    /// A purple CI color transfers the blue tones into purple tones (red and blue dominate green).
    /// </summary>
    [TestMethod]
    public void GetBackgroundImagePng_ConfiguredPurple_ShiftsBlueToPurple() {

      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);
      builder.BackgroundCiColor = "#8000ff";

      PngPixels original = PngImageCodec.Decode(TemplateAuthPageBuilder.GetBackgroundImagePng(null));
      PngPixels purple = PngImageCodec.Decode(TemplateAuthPageBuilder.GetBackgroundImagePng("8000ff"));

      Assert.AreEqual(original.Width, purple.Width);
      Assert.AreEqual(original.Height, purple.Height);

      long red = 0;
      long green = 0;
      for (int i = 0; i < purple.Pixels.Length; i += purple.BytesPerPixel * 101) {
        red += purple.Pixels[i];
        green += purple.Pixels[i + 1];
      }
      Assert.IsTrue(red > green, "purple tones expected");
    }

    /// <summary>
    /// The controls take the hue of the CI color, while the lightness is scaled into a readable range.
    /// </summary>
    [TestMethod]
    public void GetAuthForm_CiColor_AppliedToControlsWithScaledIntensity() {

      TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);
      builder.BackgroundCiColor = "#ffffff";

      string html = builder.GetAuthForm("code", "", "", "", "c", "https://app/cb", "", new AuthPageViewModeOptions(), "");

      Assert.IsFalse(html.Contains("--ath-accent: #2f7a92"), "the default accent must be replaced");
      Assert.IsTrue(html.Contains("--ath-accent: #707070"), "white must be scaled to a readable gray");
      Assert.IsTrue(html.Contains("--ath-accent-text: #ffffff"));

      builder.BackgroundCiColor = "#8000ff";
      string purpleHtml = builder.GetAuthForm("code", "", "", "", "c", "https://app/cb", "", new AuthPageViewModeOptions(), "");
      Assert.IsTrue(purpleHtml.Contains("--ath-accent-focus: rgba("));
      Assert.IsFalse(purpleHtml.Contains("--ath-accent: #2f7a92"));
    }

    /// <summary>
    /// Unconfigured or invalid colors are not served (protection against expensive transformations).
    /// </summary>
    [TestMethod]
    public void GetBackgroundImagePng_UnconfiguredOrInvalidColor_ReturnsNull() {

      Assert.IsNull(TemplateAuthPageBuilder.GetBackgroundImagePng("123457"));
      Assert.IsNull(TemplateAuthPageBuilder.GetBackgroundImagePng("nocolor"));
      Assert.ThrowsException<ArgumentException>(() => {
        TemplateAuthPageBuilder builder = new TemplateAuthPageBuilder("Title", null, null);
        builder.BackgroundCiColor = "red";
      });
    }

  }

}
