using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;

namespace Security.AccessTokenHandling.OAuth.Server {

  public partial class TemplateAuthPageBuilder {

    /// <summary>
    /// The (relative) url, under which the 'OAuth2Controller' serves the background image.
    /// It is relative to the page url (/oauth2/authorize and /oauth2/sso/authorize), so that
    /// a host-specific path base (virtual directory) is respected automatically.
    /// </summary>
    public const string BackgroundImageRelativeUrl = "./background.png";

    private const string _BackgroundImageResourceName = "AuthTokenHandling.OAuthBG.png";

    private const string _OriginalBackgroundCacheKey = "original";

    private const int _MaxCachedBackgroundVariants = 32;

    /// <summary>
    /// In-memory cache of the (transformed) background images, keyed by the normalized CI color
    /// ('original' for the untransformed embedded image).
    /// </summary>
    private static readonly ConcurrentDictionary<string, Lazy<byte[]>> _BackgroundImageCache = (
      new ConcurrentDictionary<string, Lazy<byte[]>>(StringComparer.Ordinal)
    );

    /// <summary>
    /// The CI colors, which were configured by any builder instance - only these variants are served by
    /// the background endpoint (protects the server against expensive transformations of arbitrary colors).
    /// </summary>
    private static readonly ConcurrentDictionary<string, bool> _RegisteredBackgroundColors = (
      new ConcurrentDictionary<string, bool>(StringComparer.Ordinal)
    );

    private bool _ShowBackgroundImage = true;
    private string _BackgroundCiColor = null;
    private string _CustomBackgroundImageUrl = null;

    /// <summary>
    /// Enables the (zoomed) background image on full-page views (default: true).
    /// The background is never shown in the 'LowSpaceEmbedded' view mode.
    /// </summary>
    public bool ShowBackgroundImage {
      get {
        return _ShowBackgroundImage;
      }
      set {
        _ShowBackgroundImage = value;
      }
    }

    /// <summary>
    /// OPTIONAL: a CI color (e.g. '#7b2cbf'), which is applied to the embedded background image:
    /// the hue of each pixel is replaced by the hue of the CI color and its saturation is scaled by the
    /// saturation of the CI color, while the lightness (structure of the image) is preserved.
    /// So a neutral color (e.g. dark gray) removes the whole blue, while a purple color transfers the blue
    /// tones into purple tones. Null (default): the original (blue) image is used.
    /// Additionally the controls (buttons, input borders, focus ring, checkboxes) are colored with the CI color,
    /// whose lightness is scaled into a readable range (see 'ApplyCiColorToControls').
    /// </summary>
    public string BackgroundCiColor {
      get {
        return _BackgroundCiColor;
      }
      set {

        if (string.IsNullOrWhiteSpace(value)) {
          _BackgroundCiColor = null;
          return;
        }

        string normalized = NormalizeBackgroundColor(value);
        _RegisteredBackgroundColors.TryAdd(normalized, true);
        _BackgroundCiColor = normalized;
      }
    }

    /// <summary>
    /// OPTIONAL: the url of a custom background image, which replaces the embedded one
    /// (it is used as given, so no CI color transformation is applied to it).
    /// </summary>
    public string CustomBackgroundImageUrl {
      get {
        return _CustomBackgroundImageUrl;
      }
      set {

        if (string.IsNullOrWhiteSpace(value)) {
          _CustomBackgroundImageUrl = null;
        } else {
          _CustomBackgroundImageUrl = value.Trim();
        }

      }
    }

    /// <summary>
    /// Returns the css-safe url of the background image for the current configuration
    /// (or null, if no background image should be shown).
    /// </summary>
    private string GetBackgroundImageUrl(AuthPageViewModeOptions viewMode) {

      if (!_ShowBackgroundImage || viewMode.LowSpaceEmbedded) {
        return null;
      }

      if (_CustomBackgroundImageUrl != null) {
        return EscapeCssUrl(_CustomBackgroundImageUrl);
      }

      if (_BackgroundCiColor == null) {
        return BackgroundImageRelativeUrl;
      }

      //the '#' is omitted, so that no url-encoding is required
      return BackgroundImageRelativeUrl + "?ci=" + _BackgroundCiColor.Substring(1);
    }

    /// <summary>
    /// Returns the PNG bytes of the embedded background image - transformed by the given CI color
    /// (null/empty: original image). The result is cached in memory. Returns null, if the CI color
    /// is invalid or was not configured by any 'TemplateAuthPageBuilder' (see 'BackgroundCiColor').
    /// </summary>
    public static byte[] GetBackgroundImagePng(string ciColor) {

      string cacheKey;

      if (string.IsNullOrWhiteSpace(ciColor)) {
        cacheKey = _OriginalBackgroundCacheKey;
      } else {

        if (!TryNormalizeBackgroundColor(ciColor, out cacheKey)) {
          return null;
        }

        if (!_RegisteredBackgroundColors.ContainsKey(cacheKey)) {
          return null;
        }

      }

      if (!_BackgroundImageCache.ContainsKey(cacheKey) && _BackgroundImageCache.Count >= _MaxCachedBackgroundVariants) {
        return null;
      }

      Lazy<byte[]> entry = _BackgroundImageCache.GetOrAdd(
        cacheKey, (key) => new Lazy<byte[]>(() => CreateBackgroundImagePng(key))
      );

      return entry.Value;
    }

    /// <summary>
    /// Loads the embedded background image and applies the CI color transformation (if requested).
    /// </summary>
    private static byte[] CreateBackgroundImagePng(string cacheKey) {

      byte[] original = LoadEmbeddedBackgroundImage();

      if (cacheKey == _OriginalBackgroundCacheKey) {
        return original;
      }

      PngPixels image = PngImageCodec.Decode(original);
      ApplyCiColor(image, cacheKey);

      return PngImageCodec.Encode(image);
    }

    /// <summary>
    /// Reads the embedded 'OAuthBG.png'.
    /// </summary>
    private static byte[] LoadEmbeddedBackgroundImage() {

      Assembly assembly = typeof(TemplateAuthPageBuilder).Assembly;

      using (Stream resourceStream = assembly.GetManifestResourceStream(_BackgroundImageResourceName)) {

        if (resourceStream == null) {
          throw new InvalidOperationException("The embedded resource '" + _BackgroundImageResourceName + "' was not found.");
        }

        using (MemoryStream buffer = new MemoryStream()) {
          resourceStream.CopyTo(buffer);
          return buffer.ToArray();
        }

      }

    }

    /// <summary>
    /// Re-colors all pixels (in place): hue := hue of the CI color, saturation := pixel saturation * CI saturation,
    /// lightness := pixel lightness.
    /// </summary>
    private static void ApplyCiColor(PngPixels image, string normalizedColor) {

      int ciR = int.Parse(normalizedColor.Substring(1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
      int ciG = int.Parse(normalizedColor.Substring(3, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
      int ciB = int.Parse(normalizedColor.Substring(5, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);

      double ciHue;
      double ciSaturation;
      double ciLightness;
      RgbToHsl(ciR, ciG, ciB, out ciHue, out ciSaturation, out ciLightness);

      byte[] pixels = image.Pixels;
      int bpp = image.BytesPerPixel;

      for (int i = 0; i + 2 < pixels.Length; i += bpp) {

        double hue;
        double saturation;
        double lightness;
        RgbToHsl(pixels[i], pixels[i + 1], pixels[i + 2], out hue, out saturation, out lightness);

        byte r;
        byte g;
        byte b;
        HslToRgb(ciHue, saturation * ciSaturation, lightness, out r, out g, out b);

        pixels[i] = r;
        pixels[i + 1] = g;
        pixels[i + 2] = b;
      }

    }

    /// <summary>
    /// Colors the controls (buttons, input fields, focus ring) with the CI color. The hue is taken as given,
    /// while saturation and lightness are scaled LINEARLY into ranges, which keep the controls readable
    /// (so a very light CI color does not lead to an invisible button, but different CI intensities
    /// still result in different control intensities).
    /// </summary>
    private static void ApplyCiColorToControls(AuthPageModel model, string normalizedColor, bool darkmode) {

      int ciR = int.Parse(normalizedColor.Substring(1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
      int ciG = int.Parse(normalizedColor.Substring(3, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
      int ciB = int.Parse(normalizedColor.Substring(5, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);

      double ciHue;
      double ciSaturation;
      double ciLightness;
      RgbToHsl(ciR, ciG, ciB, out ciHue, out ciSaturation, out ciLightness);

      //the saturation is capped, so that the controls do not look garish
      double accentSaturation = ciSaturation * 0.85;

      double accentLightness;
      double inputLightness;
      double borderLightness;

      if (darkmode) {
        //lightness 0..1 => 0.38..0.58 (bright enough on the dark card)
        accentLightness = 0.38 + (ciLightness * 0.20);
        inputLightness = 0.15;
        borderLightness = 0.30;
      } else {
        //lightness 0..1 => 0.24..0.44 (dark enough on the white card)
        accentLightness = 0.24 + (ciLightness * 0.20);
        inputLightness = 0.985;
        borderLightness = 0.84;
      }

      byte r;
      byte g;
      byte b;

      HslToRgb(ciHue, accentSaturation, accentLightness, out r, out g, out b);
      model.AccentColor = ToHexColor(r, g, b);
      model.AccentFocusColor = "rgba(" + r.ToString(CultureInfo.InvariantCulture) + ", " + g.ToString(CultureInfo.InvariantCulture) + ", " + b.ToString(CultureInfo.InvariantCulture) + ", 0.30)";

      //the text on the button must be readable (e.g. a yellow accent needs dark text)
      if (GetRelativeLuminance(r, g, b) > 0.35) {
        model.AccentTextColor = "#1a1a1a";
      } else {
        model.AccentTextColor = "#ffffff";
      }

      HslToRgb(ciHue, ciSaturation * 0.30, inputLightness, out r, out g, out b);
      model.InputColor = ToHexColor(r, g, b);

      HslToRgb(ciHue, ciSaturation * 0.35, borderLightness, out r, out g, out b);
      model.BorderColor = ToHexColor(r, g, b);
    }

    /// <summary>
    /// The relative luminance according to WCAG 2.x (0 = black, 1 = white).
    /// </summary>
    private static double GetRelativeLuminance(byte red, byte green, byte blue) {

      double r = ToLinearChannel(red);
      double g = ToLinearChannel(green);
      double b = ToLinearChannel(blue);

      return (0.2126 * r) + (0.7152 * g) + (0.0722 * b);
    }

    private static double ToLinearChannel(byte value) {

      double c = value / 255.0;

      if (c <= 0.03928) {
        return c / 12.92;
      }
      return Math.Pow((c + 0.055) / 1.055, 2.4);
    }

    private static string ToHexColor(byte red, byte green, byte blue) {
      return "#" + red.ToString("x2", CultureInfo.InvariantCulture) + green.ToString("x2", CultureInfo.InvariantCulture) + blue.ToString("x2", CultureInfo.InvariantCulture);
    }

    private static void RgbToHsl(int red, int green, int blue, out double hue, out double saturation, out double lightness) {

      double r = red / 255.0;
      double g = green / 255.0;
      double b = blue / 255.0;
      double max = Math.Max(r, Math.Max(g, b));
      double min = Math.Min(r, Math.Min(g, b));
      double delta = max - min;

      lightness = (max + min) / 2.0;

      if (delta <= 0.0) {
        hue = 0.0;
        saturation = 0.0;
        return;
      }

      if (lightness > 0.5) {
        saturation = delta / (2.0 - max - min);
      } else {
        saturation = delta / (max + min);
      }

      if (max == r) {
        hue = (g - b) / delta;
        if (g < b) {
          hue += 6.0;
        }
      } else if (max == g) {
        hue = ((b - r) / delta) + 2.0;
      } else {
        hue = ((r - g) / delta) + 4.0;
      }

      hue = hue / 6.0;
    }

    private static void HslToRgb(double hue, double saturation, double lightness, out byte red, out byte green, out byte blue) {

      if (saturation <= 0.0) {
        byte gray = ToByte(lightness);
        red = gray;
        green = gray;
        blue = gray;
        return;
      }

      double q;
      if (lightness < 0.5) {
        q = lightness * (1.0 + saturation);
      } else {
        q = lightness + saturation - (lightness * saturation);
      }
      double p = (2.0 * lightness) - q;

      red = ToByte(HueToChannel(p, q, hue + (1.0 / 3.0)));
      green = ToByte(HueToChannel(p, q, hue));
      blue = ToByte(HueToChannel(p, q, hue - (1.0 / 3.0)));
    }

    private static double HueToChannel(double p, double q, double t) {

      if (t < 0.0) {
        t += 1.0;
      }
      if (t > 1.0) {
        t -= 1.0;
      }

      if (t < 1.0 / 6.0) {
        return p + ((q - p) * 6.0 * t);
      }
      if (t < 0.5) {
        return q;
      }
      if (t < 2.0 / 3.0) {
        return p + ((q - p) * ((2.0 / 3.0) - t) * 6.0);
      }
      return p;
    }

    private static byte ToByte(double value) {

      int scaled = (int)Math.Round(value * 255.0);

      if (scaled < 0) {
        return 0;
      }
      if (scaled > 255) {
        return 255;
      }
      return (byte)scaled;
    }

    /// <summary>
    /// Normalizes '#rgb', '#rrggbb', 'rgb' or 'rrggbb' to '#rrggbb' (lower case).
    /// </summary>
    private static string NormalizeBackgroundColor(string color) {

      string normalized;

      if (!TryNormalizeBackgroundColor(color, out normalized)) {
        throw new ArgumentException("The CI color '" + color + "' is invalid (expected: '#rrggbb' or '#rgb').", nameof(color));
      }

      return normalized;
    }

    private static bool TryNormalizeBackgroundColor(string color, out string normalized) {

      normalized = null;

      if (color == null) {
        return false;
      }

      string hex = color.Trim();
      if (hex.StartsWith("#", StringComparison.Ordinal)) {
        hex = hex.Substring(1);
      }

      if (hex.Length == 3) {
        hex = new string(new char[] { hex[0], hex[0], hex[1], hex[1], hex[2], hex[2] });
      }

      if (hex.Length != 6) {
        return false;
      }

      foreach (char c in hex) {
        if (!Uri.IsHexDigit(c)) {
          return false;
        }
      }

      normalized = "#" + hex.ToLowerInvariant();
      return true;
    }

    /// <summary>
    /// Escapes all characters, which could break out of a css 'url("...")' or the surrounding style element.
    /// </summary>
    private static string EscapeCssUrl(string url) {

      StringBuilder sb = new StringBuilder(url.Length);

      foreach (char c in url) {
        if (c == '"' || c == '\'' || c == '(' || c == ')' || c == '\\' || c == '<' || c == '>' || char.IsWhiteSpace(c) || char.IsControl(c)) {
          sb.Append('%');
          sb.Append(((int)c).ToString("X2", CultureInfo.InvariantCulture));
        } else {
          sb.Append(c);
        }
      }

      return sb.ToString();
    }

  }

}
