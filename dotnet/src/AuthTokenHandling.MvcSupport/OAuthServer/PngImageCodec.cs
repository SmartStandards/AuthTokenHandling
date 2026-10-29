using System;
using System.IO;
using System.IO.Compression;

namespace Security.AccessTokenHandling.OAuth.Server {

  /// <summary>
  /// Minimal, dependency-free PNG codec (8 bit, RGB / RGBA, non-interlaced), which is just sufficient
  /// to recolor the OAuth background image without depending on 'System.Drawing' (not supported on non-Windows servers)
  /// or on a third-party imaging library.
  /// </summary>
  internal static class PngImageCodec {

    private static readonly byte[] _Signature = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 };

    private static readonly uint[] _CrcTable = CreateCrcTable();

    /// <summary>
    /// Decodes a PNG into raw (unfiltered) pixel rows.
    /// </summary>
    public static PngPixels Decode(byte[] png) {

      if (png == null || png.Length < _Signature.Length) {
        throw new ArgumentException("The given data is not a PNG image.", nameof(png));
      }

      for (int i = 0; i < _Signature.Length; i++) {
        if (png[i] != _Signature[i]) {
          throw new ArgumentException("The given data is not a PNG image.", nameof(png));
        }
      }

      int width = 0;
      int height = 0;
      int bytesPerPixel = 0;
      byte colorType = 0;
      MemoryStream compressedData = new MemoryStream();

      int offset = _Signature.Length;
      while (offset + 8 <= png.Length) {

        int chunkLength = ReadInt32BigEndian(png, offset);
        string chunkType = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);
        int dataOffset = offset + 8;

        if (chunkType == "IHDR") {

          width = ReadInt32BigEndian(png, dataOffset);
          height = ReadInt32BigEndian(png, dataOffset + 4);
          byte bitDepth = png[dataOffset + 8];
          colorType = png[dataOffset + 9];
          byte interlace = png[dataOffset + 12];

          if (bitDepth != 8 || interlace != 0) {
            throw new NotSupportedException("Only 8 bit, non-interlaced PNG images are supported.");
          }

          if (colorType == 2) {
            bytesPerPixel = 3;
          } else if (colorType == 6) {
            bytesPerPixel = 4;
          } else {
            throw new NotSupportedException("Only RGB and RGBA PNG images are supported.");
          }

        } else if (chunkType == "IDAT") {
          compressedData.Write(png, dataOffset, chunkLength);
        } else if (chunkType == "IEND") {
          break;
        }

        offset = dataOffset + chunkLength + 4;
      }

      if (bytesPerPixel == 0) {
        throw new ArgumentException("The PNG image has no header.", nameof(png));
      }

      int stride = width * bytesPerPixel;
      byte[] filtered = new byte[(stride + 1) * height];

      compressedData.Position = 0;
      using (ZLibStream inflater = new ZLibStream(compressedData, CompressionMode.Decompress)) {
        int totalRead = 0;
        while (totalRead < filtered.Length) {
          int read = inflater.Read(filtered, totalRead, filtered.Length - totalRead);
          if (read == 0) {
            break;
          }
          totalRead += read;
        }
        if (totalRead < filtered.Length) {
          throw new InvalidDataException("The PNG image data is truncated.");
        }
      }

      byte[] pixels = new byte[stride * height];
      Unfilter(filtered, pixels, stride, height, bytesPerPixel);

      return new PngPixels(width, height, bytesPerPixel, colorType, pixels);
    }

    /// <summary>
    /// Encodes raw pixel rows into a PNG (using the 'Paeth' filter for all rows).
    /// </summary>
    public static byte[] Encode(PngPixels image) {

      int stride = image.Width * image.BytesPerPixel;
      byte[] filtered = new byte[(stride + 1) * image.Height];
      byte[] pixels = image.Pixels;
      int bpp = image.BytesPerPixel;

      for (int y = 0; y < image.Height; y++) {

        int rowStart = y * stride;
        int targetStart = y * (stride + 1);
        filtered[targetStart] = 4;

        for (int x = 0; x < stride; x++) {

          int left = 0;
          int up = 0;
          int upLeft = 0;

          if (x >= bpp) {
            left = pixels[rowStart + x - bpp];
          }
          if (y > 0) {
            up = pixels[rowStart - stride + x];
            if (x >= bpp) {
              upLeft = pixels[rowStart - stride + x - bpp];
            }
          }

          filtered[targetStart + 1 + x] = (byte)(pixels[rowStart + x] - PaethPredictor(left, up, upLeft));
        }

      }

      MemoryStream compressed = new MemoryStream();
      using (ZLibStream deflater = new ZLibStream(compressed, CompressionLevel.Optimal, true)) {
        deflater.Write(filtered, 0, filtered.Length);
      }

      byte[] header = new byte[13];
      WriteInt32BigEndian(header, 0, image.Width);
      WriteInt32BigEndian(header, 4, image.Height);
      header[8] = 8;
      header[9] = image.ColorType;
      header[10] = 0;
      header[11] = 0;
      header[12] = 0;

      MemoryStream output = new MemoryStream();
      output.Write(_Signature, 0, _Signature.Length);
      WriteChunk(output, "IHDR", header, header.Length);
      WriteChunk(output, "IDAT", compressed.GetBuffer(), (int)compressed.Length);
      WriteChunk(output, "IEND", new byte[0], 0);

      return output.ToArray();
    }

    private static void Unfilter(byte[] filtered, byte[] pixels, int stride, int height, int bpp) {

      for (int y = 0; y < height; y++) {

        int sourceStart = y * (stride + 1);
        byte filterType = filtered[sourceStart];
        int rowStart = y * stride;

        for (int x = 0; x < stride; x++) {

          int raw = filtered[sourceStart + 1 + x];
          int left = 0;
          int up = 0;
          int upLeft = 0;

          if (x >= bpp) {
            left = pixels[rowStart + x - bpp];
          }
          if (y > 0) {
            up = pixels[rowStart - stride + x];
            if (x >= bpp) {
              upLeft = pixels[rowStart - stride + x - bpp];
            }
          }

          int value;
          switch (filterType) {
            case 0:
              value = raw;
              break;
            case 1:
              value = raw + left;
              break;
            case 2:
              value = raw + up;
              break;
            case 3:
              value = raw + ((left + up) >> 1);
              break;
            case 4:
              value = raw + PaethPredictor(left, up, upLeft);
              break;
            default:
              throw new InvalidDataException("Unknown PNG filter type " + filterType.ToString() + ".");
          }

          pixels[rowStart + x] = (byte)value;
        }

      }

    }

    private static int PaethPredictor(int a, int b, int c) {

      int p = a + b - c;
      int pa = Math.Abs(p - a);
      int pb = Math.Abs(p - b);
      int pc = Math.Abs(p - c);

      if (pa <= pb && pa <= pc) {
        return a;
      }
      if (pb <= pc) {
        return b;
      }
      return c;
    }

    private static void WriteChunk(Stream output, string chunkType, byte[] data, int length) {

      byte[] lengthBytes = new byte[4];
      WriteInt32BigEndian(lengthBytes, 0, length);
      byte[] typeBytes = System.Text.Encoding.ASCII.GetBytes(chunkType);

      output.Write(lengthBytes, 0, 4);
      output.Write(typeBytes, 0, 4);
      output.Write(data, 0, length);

      uint crc = 0xFFFFFFFFu;
      crc = UpdateCrc(crc, typeBytes, 4);
      crc = UpdateCrc(crc, data, length);
      crc = crc ^ 0xFFFFFFFFu;

      byte[] crcBytes = new byte[4];
      WriteInt32BigEndian(crcBytes, 0, unchecked((int)crc));
      output.Write(crcBytes, 0, 4);
    }

    private static uint UpdateCrc(uint crc, byte[] data, int length) {

      for (int i = 0; i < length; i++) {
        crc = _CrcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
      }

      return crc;
    }

    private static uint[] CreateCrcTable() {

      uint[] table = new uint[256];

      for (uint n = 0; n < 256; n++) {
        uint c = n;
        for (int k = 0; k < 8; k++) {
          if ((c & 1) != 0) {
            c = 0xEDB88320u ^ (c >> 1);
          } else {
            c = c >> 1;
          }
        }
        table[n] = c;
      }

      return table;
    }

    private static int ReadInt32BigEndian(byte[] buffer, int offset) {
      return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
    }

    private static void WriteInt32BigEndian(byte[] buffer, int offset, int value) {
      buffer[offset] = (byte)(value >> 24);
      buffer[offset + 1] = (byte)(value >> 16);
      buffer[offset + 2] = (byte)(value >> 8);
      buffer[offset + 3] = (byte)value;
    }

  }

  /// <summary>
  /// Raw (unfiltered) pixel rows of a PNG image.
  /// </summary>
  internal sealed class PngPixels {

    private readonly int _Width;
    private readonly int _Height;
    private readonly int _BytesPerPixel;
    private readonly byte _ColorType;
    private readonly byte[] _Pixels;

    public PngPixels(int width, int height, int bytesPerPixel, byte colorType, byte[] pixels) {
      _Width = width;
      _Height = height;
      _BytesPerPixel = bytesPerPixel;
      _ColorType = colorType;
      _Pixels = pixels;
    }

    public int Width {
      get {
        return _Width;
      }
    }

    public int Height {
      get {
        return _Height;
      }
    }

    public int BytesPerPixel {
      get {
        return _BytesPerPixel;
      }
    }

    public byte ColorType {
      get {
        return _ColorType;
      }
    }

    public byte[] Pixels {
      get {
        return _Pixels;
      }
    }

  }

}
