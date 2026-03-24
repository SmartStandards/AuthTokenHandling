using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling.OAuth {

  /// <summary>
  /// Conform to https://www.rfc-editor.org/rfc/rfc6749#section-5.1
  /// </summary>
  public class TokenIssuingResult {

    public string access_token { get; set; }

    public string scope { get; set; }

    public string token_type { get; set; }

    /// <summary>
    /// Seconds until expiration! Not a Unix timestamp or DateTime! (conform to RFC 6749)
    /// </summary>
    public int expires_in { get; set; }

    public string id_token { get; set; }

    public string refresh_token { get; set; }

    public string error { get; set; }

    public string error_description { get; set; }

    #region  " ToString (Url-Serialization) "

    /// <summary>
    /// Returns an URL-encoded string representation of the token result,
    /// suitable for appending to a redirect URI. (has no leading ? or &)
    /// </summary>
    /// <returns></returns>
    public override string ToString() {
      StringBuilder sb = new StringBuilder(300);
      sb.Append("access_token=");
      sb.Append(access_token);

      if (!string.IsNullOrWhiteSpace(scope)) {
        sb.Append("&scope=");
        sb.Append(scope);
      }
      if (!string.IsNullOrWhiteSpace(token_type)) {
        sb.Append("&token_type=");
        sb.Append(token_type);
      }
      if (expires_in > 0) {
        sb.Append("&expires_in=");
        sb.Append(expires_in.ToString());
      }
      if (!string.IsNullOrWhiteSpace(id_token)) {
        sb.Append("&id_token=");
        sb.Append(id_token);
      }
      if (!string.IsNullOrWhiteSpace(refresh_token)) {
        sb.Append("&refresh_token=");
        sb.Append(refresh_token);
      }
      if (!string.IsNullOrWhiteSpace(error)) {
        sb.Append("&error=");
        sb.Append(error);
      }
      if (!string.IsNullOrWhiteSpace(error_description)) {
        sb.Append("&error_description=");
        sb.Append(error_description);
      }
      return sb.ToString();
    }

    #endregion

    public static TokenIssuingResult FromError(string error, string description = null) {

      if (string.IsNullOrWhiteSpace(error) && !string.IsNullOrWhiteSpace(description)) {
        error = description;
      }
      else if (string.IsNullOrWhiteSpace(description) && !string.IsNullOrWhiteSpace(error)) {
        description = error;
      }

      return new TokenIssuingResult() {
        error = error,
        error_description = description
      };
    }

  }

}
