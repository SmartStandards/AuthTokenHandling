using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Text;

namespace AuthTokenHandling.TestApp.Services {

  /// <summary>
  /// Decodes JWTs for display purposes (WITHOUT signature validation - use an introspector for that).
  /// </summary>
  internal static class JwtInspector {

    /// <summary>
    /// Returns an object with 'isJwt', 'header', 'payload' and 'times' (human readable 'iat'/'nbf'/'exp').
    /// Tokens which are no JWTs are reported as opaque.
    /// </summary>
    public static JObject Decode(string rawToken) {

      JObject result = new JObject();
      result["isJwt"] = false;

      if (string.IsNullOrWhiteSpace(rawToken)) {
        result["info"] = "(empty)";
        return result;
      }

      string token = rawToken.Trim();
      if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
        token = token.Substring(7).Trim();
      }

      string[] segments = token.Split('.');
      if (segments.Length < 2) {
        result["info"] = "Opaque token (no JWT structure).";
        return result;
      }

      JObject header;
      JObject payload;
      try {
        header = JObject.Parse(DecodeBase64Url(segments[0]));
        payload = JObject.Parse(DecodeBase64Url(segments[1]));
      } catch (Exception ex) when (ex is FormatException || ex is JsonReaderException) {
        result["info"] = "Opaque token (segments are no Base64Url encoded JSON): " + ex.Message;
        return result;
      }

      result["isJwt"] = true;
      result["header"] = header;
      result["payload"] = payload;

      JObject times = new JObject();
      AddTime(times, payload, "iat");
      AddTime(times, payload, "nbf");
      AddTime(times, payload, "exp");

      JToken expToken = payload["exp"];
      if (expToken != null && (expToken.Type == JTokenType.Integer || expToken.Type == JTokenType.Float)) {
        DateTime expUtc = DateTimeOffset.FromUnixTimeSeconds(expToken.Value<long>()).UtcDateTime;
        if (expUtc < DateTime.UtcNow) {
          times["state"] = "EXPIRED";
        } else {
          times["state"] = "valid for " + Math.Round((expUtc - DateTime.UtcNow).TotalMinutes, 1) + " min";
        }
      }

      result["times"] = times;
      return result;
    }

    /// <summary>
    /// Adds a local, human readable representation of a unix timestamp claim.
    /// </summary>
    private static void AddTime(JObject target, JObject payload, string claimName) {

      JToken value = payload[claimName];
      if (value == null) {
        return;
      }

      if (value.Type != JTokenType.Integer && value.Type != JTokenType.Float) {
        return;
      }

      DateTime localTime = DateTimeOffset.FromUnixTimeSeconds(value.Value<long>()).LocalDateTime;
      target[claimName] = localTime.ToString("yyyy-MM-dd HH:mm:ss");

    }

    /// <summary>
    /// Decodes a Base64Url encoded UTF8 string.
    /// </summary>
    private static string DecodeBase64Url(string segment) {

      string base64 = segment.Replace('-', '+').Replace('_', '/');

      int padding = base64.Length % 4;
      if (padding == 2) {
        base64 = base64 + "==";
      } else if (padding == 3) {
        base64 = base64 + "=";
      }

      byte[] bytes = Convert.FromBase64String(base64);
      return Encoding.UTF8.GetString(bytes);
    }

  }

}
