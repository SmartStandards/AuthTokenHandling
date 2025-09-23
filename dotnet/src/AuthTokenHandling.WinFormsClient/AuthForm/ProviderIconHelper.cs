using Logging.SmartStandards;
using Logging.SmartStandards.CopyForAuthTokenHandling;
using Microsoft.VisualBasic;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Text;

namespace System.Drawing {

  /// <summary>
  /// Provides factory methods to create System.Drawing.Icon instances from http(s) or data: URLs.
  /// Supports ICO directly and converts common raster images (PNG/JPG/GIF/BMP) to icons at a given size.
  /// </summary>
  internal static class ProviderIconHelper {

    //only for fallback.icon
    private static ComponentResourceManager _AuthFormResources = null;

    public static Icon GetProviderIcon(this IOAuthOperationsProvider provider) {

      if (!string.IsNullOrEmpty(provider.ProviderIconUrl)) {
        try {
          return CreateFromUrl(provider.ProviderIconUrl, 32);
        }
        catch {
        }
      }

      if (_AuthFormResources == null) {
        _AuthFormResources = new System.ComponentModel.ComponentResourceManager(typeof(AuthForm));
      }
      //fallback goes on default icon of the AuthForm
      return (Icon)_AuthFormResources.GetObject("$this.Icon");

    }
    /// <summary>
    /// Default icon size in pixels (width and height).
    /// </summary>
    public const int _DefaultIconSize = 32;

    /// <summary>
    /// Creates an Icon from a given HTTP(S) or data: URL using the default size (32x32).
    /// </summary>
    /// <param name="url">HTTP(S) or data: URL string.</param>
    /// <returns>New Icon instance.</returns>
    public static Icon CreateFromUrl(string url) {
      return CreateFromUrl(url, _DefaultIconSize);
    }

    /// <summary>
    /// Creates an Icon from a given HTTP(S) or data: URL at the specified square size.
    /// Avoids any interop; produces a managed ICO (PNG-compressed) when needed.
    /// </summary>
    /// <param name="url">HTTP(S) or data: URL string.</param>
    /// <param name="size">Target icon size in pixels (e.g., 16, 24, 32, 48, 64, 128, 256).</param>
    /// <returns>New Icon instance.</returns>
    public static Icon CreateFromUrl(string url, int size) {
      DevLogger.LogTrace(0, 99999, "IconFactory.CreateFromUrl entered.");

      if (url == null) {
        throw new ArgumentNullException("url", "URL must not be null.");
      }

      if (size <= 0 || size > 256) {
        throw new ArgumentOutOfRangeException("size", "Size must be between 1 and 256.");
      }

      try {
        byte[] payload = FetchBytes(url);
        if (payload == null) {
          throw new InvalidOperationException("No data could be obtained from the provided URL.");
        }

        if (IsIcoData(payload)) {
          // Bereits ein ICO: direkt laden; optional kannst du hier noch auf die gewünschte Größe neu packen.
          using (MemoryStream icoStream = new MemoryStream(payload, false)) {
            Icon icon = new Icon(icoStream);
            return (Icon)icon.Clone();
          }
        }
        else {
          // Rasterdaten -> Bild laden, skalieren, als PNG speichern und als ICO (PNG-in-ICO) verpacken.
          byte[] pngBytes = RasterToPngBytes(payload, size);
          byte[] icoBytes = BuildSingleImageIcoFromPng(pngBytes, size, size, 32);
          using (MemoryStream icoStream = new MemoryStream(icoBytes, false)) {
            Icon icon = new Icon(icoStream);
            return (Icon)icon.Clone();
          }
        }
      }
      catch (Exception ex) {
        DevLogger.LogCritical(ex);
        throw;
      }
    }

    /// <summary>
    /// Returns true if the data looks like an ICO file (begins with 00 00 01 00).
    /// </summary>
    private static bool IsIcoData(byte[] data) {
      if (data == null) {
        return false;
      }
      if (data.Length < 4) {
        return false;
      }
      if (data[0] == 0 && data[1] == 0 && data[2] == 1 && data[3] == 0) {
        return true;
      }
      return false;
    }

    /// <summary>
    /// Fetches raw bytes from an HTTP(S) URL or a data: URL.
    /// </summary>
    private static byte[] FetchBytes(string url) {
      if (url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) {
        return ParseDataUrl(url);
      }
      if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
        return DownloadHttp(url);
      }
      throw new ArgumentException("Only http(s) and data: URLs are supported.", "url");
    }

    /// <summary>
    /// Downloads data from HTTP(S) synchronously with explicit timeouts and redirection allowed.
    /// </summary>
    private static byte[] DownloadHttp(string url) {
      DevLogger.LogTrace(0, 99999, "IconFactory.DownloadHttp entered.");

      HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
      request.Method = "GET";
      request.UserAgent = "IconFactory/NoInterop/1.0";
      request.Timeout = 15000;
      request.ReadWriteTimeout = 15000;
      request.AllowAutoRedirect = true;

      using (WebResponse response = request.GetResponse()) {
        using (Stream stream = response.GetResponseStream()) {
          if (stream == null) {
            throw new IOException("The HTTP response stream was null.");
          }
          using (MemoryStream ms = new MemoryStream()) {
            CopyTo(stream, ms);
            return ms.ToArray();
          }
        }
      }
    }

    /// <summary>
    /// Parses a data: URL into raw bytes. Supports base64 and URL-encoded payloads.
    /// </summary>
    private static byte[] ParseDataUrl(string dataUrl) {
      DevLogger.LogTrace(0, 99999, "IconFactory.ParseDataUrl entered.");

      int commaIndex = dataUrl.IndexOf(',');
      if (commaIndex <= 4) {
        throw new FormatException("The data: URL is malformed (no comma separator found).");
      }

      string metadata = dataUrl.Substring(5, commaIndex - 5);
      string payload = dataUrl.Substring(commaIndex + 1);

      bool isBase64 = metadata.EndsWith(";base64", StringComparison.OrdinalIgnoreCase);

      if (isBase64) {
        try {
          return Convert.FromBase64String(payload);
        }
        catch (FormatException ex) {
          DevLogger.LogCritical(ex);
          throw new FormatException("The base64 payload in the data: URL is invalid.", ex);
        }
      }
      else {
        string decoded = Uri.UnescapeDataString(payload);
        return Encoding.UTF8.GetBytes(decoded);
      }
    }

    /// <summary>
    /// Loads raster bytes (PNG/JPG/GIF/BMP), resizes to a square of the given size, and returns PNG bytes.
    /// Uses System.Drawing only for decode/resize/encode (no interop calls).
    /// </summary>
    private static byte[] RasterToPngBytes(byte[] rasterBytes, int size) {
      DevLogger.LogTrace(0, 99999, "IconFactory.RasterToPngBytes entered.");

      using (MemoryStream input = new MemoryStream(rasterBytes, false)) {
        using (System.Drawing.Image img = System.Drawing.Image.FromStream(input, true, true)) {
          using (Bitmap bmp = ResizeToSquareBitmap(img, size)) {
            using (MemoryStream outPng = new MemoryStream()) {
              bmp.Save(outPng, ImageFormat.Png);
              return outPng.ToArray();
            }
          }
        }
      }
    }

    /// <summary>
    /// Resizes an Image to a transparent square Bitmap of the target size with high-quality settings.
    /// </summary>
    private static Bitmap ResizeToSquareBitmap(System.Drawing.Image source, int size) {
      DevLogger.LogTrace(0, 99999, "IconFactory.ResizeToSquareBitmap entered.");

      if (source == null) {
        throw new ArgumentNullException("source", "Source image must not be null.");
      }
      if (size <= 0) {
        throw new ArgumentOutOfRangeException("size", "Size must be positive.");
      }

      int targetWidth = size;
      int targetHeight = size;

      double scaleX = (double)targetWidth / (double)source.Width;
      double scaleY = (double)targetHeight / (double)source.Height;
      double scale = scaleX < scaleY ? scaleX : scaleY;

      int scaledWidth = (int)Math.Round((double)source.Width * scale);
      int scaledHeight = (int)Math.Round((double)source.Height * scale);

      int offsetX = (targetWidth - scaledWidth) / 2;
      int offsetY = (targetHeight - scaledHeight) / 2;

      Bitmap canvas = new Bitmap(targetWidth, targetHeight, PixelFormat.Format32bppArgb);

      using (Graphics g = Graphics.FromImage(canvas)) {
        g.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceOver;
        g.CompositingQuality = System.Drawing.Drawing2D.CompositingQuality.HighQuality;
        g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.HighQuality;
        g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;

        Rectangle destination = new Rectangle(offsetX, offsetY, scaledWidth, scaledHeight);
        g.Clear(Color.Transparent);
        g.DrawImage(source, destination);
      }

      return canvas;
    }

    /// <summary>
    /// Builds a minimal ICO file (single image) whose image data is a PNG stream.
    /// This avoids any P/Invoke by letting Icon load a spec-compliant ICO with PNG-compressed payload.
    /// </summary>
    /// <param name="pngData">PNG byte array.</param>
    /// <param name="width">Icon width (1..256). 256 is encoded as 0 in ICO header.</param>
    /// <param name="height">Icon height (1..256). 256 is encoded as 0 in ICO header.</param>
    /// <param name="bitCount">Typically 32 for ARGB PNG.</param>
    /// <returns>ICO file bytes.</returns>
    private static byte[] BuildSingleImageIcoFromPng(byte[] pngData, int width, int height, int bitCount) {
      DevLogger.LogTrace(0, 99999, "IconFactory.BuildSingleImageIcoFromPng entered.");

      if (pngData == null || pngData.Length == 0) {
        throw new ArgumentException("pngData must not be null or empty.", "pngData");
      }
      if (width < 1 || width > 256) {
        throw new ArgumentOutOfRangeException("width", "Width must be in 1..256.");
      }
      if (height < 1 || height > 256) {
        throw new ArgumentOutOfRangeException("height", "Height must be in 1..256.");
      }
      if (bitCount <= 0) {
        throw new ArgumentOutOfRangeException("bitCount", "BitCount must be positive.");
      }

      // ICO layout:
      // ICONDIR (6 bytes)
      // ICONDIRENTRY (16 bytes) * count (here 1)
      // Image data blob (here PNG)
      using (MemoryStream ms = new MemoryStream()) {
        // ICONDIR
        WriteUInt16(ms, 0);           // Reserved
        WriteUInt16(ms, 1);           // Type: 1 = icon
        WriteUInt16(ms, 1);           // Count: 1 image

        // ICONDIRENTRY
        byte widthByte = (byte)(width == 256 ? 0 : width);
        byte heightByte = (byte)(height == 256 ? 0 : height);
        ms.WriteByte(widthByte);      // bWidth
        ms.WriteByte(heightByte);     // bHeight
        ms.WriteByte(0);              // bColorCount (0 if >= 256 colors)
        ms.WriteByte(0);              // bReserved
        WriteUInt16(ms, 1);           // wPlanes (1 for PNG payload is fine)
        WriteUInt16(ms, (ushort)bitCount); // wBitCount (32 for ARGB)
        WriteUInt32(ms, (uint)pngData.Length); // dwBytesInRes
        WriteUInt32(ms, 6 + 16);      // dwImageOffset (after header + one entry)

        // PNG data
        ms.Write(pngData, 0, pngData.Length);

        return ms.ToArray();
      }
    }

    /// <summary>
    /// Writes a little-endian UInt16 to a stream.
    /// </summary>
    private static void WriteUInt16(Stream s, ushort value) {
      byte[] b = new byte[2];
      b[0] = (byte)(value & 0xFF);
      b[1] = (byte)((value >> 8) & 0xFF);
      s.Write(b, 0, 2);
    }

    /// <summary>
    /// Writes a little-endian UInt32 to a stream.
    /// </summary>
    private static void WriteUInt32(Stream s, uint value) {
      byte[] b = new byte[4];
      b[0] = (byte)(value & 0xFF);
      b[1] = (byte)((value >> 8) & 0xFF);
      b[2] = (byte)((value >> 16) & 0xFF);
      b[3] = (byte)((value >> 24) & 0xFF);
      s.Write(b, 0, 4);
    }

    /// <summary>
    /// Copies data from one stream to another using a fixed-size buffer.
    /// </summary>
    private static void CopyTo(Stream input, Stream output) {
      byte[] buffer = new byte[81920];
      int bytesRead = 0;

      while (true) {
        bytesRead = input.Read(buffer, 0, buffer.Length);
        if (bytesRead <= 0) {
          break;
        }
        output.Write(buffer, 0, bytesRead);
      }
    }

  }

}