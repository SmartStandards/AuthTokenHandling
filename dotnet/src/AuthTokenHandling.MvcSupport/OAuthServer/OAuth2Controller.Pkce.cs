using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Web;

[assembly: InternalsVisibleTo("AuthTokenHandling.Tests")]

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // PKCE (RFC 7636) - only 'S256' is supported, PKCE itself is optional                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    private const string _PkceMethodS256 = "S256";

    /// <summary>
    /// Name of the hidden form field, which is used to pass the code challenge trough the html forms.
    /// </summary>
    private const string _PkceFormFieldName = "codeChallenge";

    /// <summary>
    /// Length of BASE64URL(SHA256(...)) without padding.
    /// </summary>
    private const int _S256ChallengeLength = 43;

    private const int _MinCodeVerifierLength = 43;
    private const int _MaxCodeVerifierLength = 128;

    /// <summary>
    /// Validates the PKCE parameters of an incoming authorize request.
    /// Returns true if PKCE is not used (both params empty) or if the params are valid.
    /// </summary>
    /// <param name="codeChallenge">the 'code_challenge' param (can be null/empty)</param>
    /// <param name="codeChallengeMethod">the 'code_challenge_method' param (can be null/empty)</param>
    /// <param name="errorDescription">null, if valid</param>
    internal static bool TryValidatePkceRequest(string codeChallenge, string codeChallengeMethod, out string errorDescription) {

      bool challengeProvided = !string.IsNullOrEmpty(codeChallenge);
      bool methodProvided = !string.IsNullOrEmpty(codeChallengeMethod);

      if (!challengeProvided && !methodProvided) {
        errorDescription = null;
        return true;
      }

      if (!challengeProvided) {
        errorDescription = "'code_challenge_method' was provided without 'code_challenge'.";
        return false;
      }

      //NOTE: according to RFC 7636 a missing method would mean 'plain', which is not supported
      if (!string.Equals(codeChallengeMethod, _PkceMethodS256, StringComparison.Ordinal)) {
        errorDescription = "Unsupported 'code_challenge_method' (only 'S256' is supported).";
        return false;
      }

      if (!IsValidS256Challenge(codeChallenge)) {
        errorDescription = "Invalid 'code_challenge' (expected BASE64URL encoded SHA256 hash).";
        return false;
      }

      errorDescription = null;
      return true;
    }

    /// <summary>
    /// Checks the format of a S256 code challenge (BASE64URL without padding, 43 chars).
    /// </summary>
    internal static bool IsValidS256Challenge(string codeChallenge) {
      if (codeChallenge == null || codeChallenge.Length != _S256ChallengeLength) {
        return false;
      }
      foreach (char c in codeChallenge) {
        bool isValidChar = (
          (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
        );
        if (!isValidChar) {
          return false;
        }
      }
      return true;
    }

    /// <summary>
    /// Checks the format of a code verifier (43-128 chars of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~").
    /// </summary>
    internal static bool IsValidCodeVerifier(string codeVerifier) {
      if (codeVerifier == null || codeVerifier.Length < _MinCodeVerifierLength || codeVerifier.Length > _MaxCodeVerifierLength) {
        return false;
      }
      foreach (char c in codeVerifier) {
        bool isValidChar = (
          (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          c == '-' || c == '.' || c == '_' || c == '~'
        );
        if (!isValidChar) {
          return false;
        }
      }
      return true;
    }

    /// <summary>
    /// Verifies the 'code_verifier' of a token request against the code challenge which was bound to the code.
    /// </summary>
    /// <param name="boundCodeChallenge">the challenge returned by the IOAuthService (null/empty if PKCE was not used)</param>
    /// <param name="codeVerifier">the 'code_verifier' param of the token request (can be null/empty)</param>
    /// <param name="errorDescription">null, if valid</param>
    internal static bool TryVerifyPkce(string boundCodeChallenge, string codeVerifier, out string errorDescription) {

      bool challengeBound = !string.IsNullOrEmpty(boundCodeChallenge);
      bool verifierProvided = !string.IsNullOrEmpty(codeVerifier);

      if (!challengeBound) {
        if (verifierProvided) {
          //downgrade protection: a verifier for a code without challenge must not be ignored
          errorDescription = "A 'code_verifier' was provided, but the code was not issued with a 'code_challenge'.";
          return false;
        }
        errorDescription = null;
        return true;
      }

      if (!verifierProvided) {
        errorDescription = "The 'code_verifier' is missing.";
        return false;
      }

      if (!IsValidCodeVerifier(codeVerifier)) {
        errorDescription = "Invalid 'code_verifier' format.";
        return false;
      }

      string computedChallenge = ComputeS256Challenge(codeVerifier);
      bool matches = CryptographicOperations.FixedTimeEquals(
        Encoding.ASCII.GetBytes(computedChallenge), Encoding.ASCII.GetBytes(boundCodeChallenge)
      );

      if (!matches) {
        errorDescription = "The 'code_verifier' does not match the 'code_challenge'.";
        return false;
      }

      errorDescription = null;
      return true;
    }

    /// <summary>
    /// Computes BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding.
    /// </summary>
    internal static string ComputeS256Challenge(string codeVerifier) {
      byte[] hash;
      using (SHA256 sha256 = SHA256.Create()) {
        hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
      }
      return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Injects the code challenge as hidden field into a html form (generated by the IAuthPageBuilder).
    /// Returns false, if the form could not be found (in this case the challenge would get lost).
    /// </summary>
    internal static bool TryInjectPkceFormField(ref string formHtml, string codeChallenge) {
      if (string.IsNullOrEmpty(codeChallenge)) {
        return true;
      }
      int formEndIndex = formHtml.IndexOf("</form>", StringComparison.OrdinalIgnoreCase);
      if (formEndIndex < 0) {
        return false;
      }
      string hiddenField = $"<input type=\"hidden\" id=\"{_PkceFormFieldName}\" name=\"{_PkceFormFieldName}\" value=\"{HttpUtility.HtmlAttributeEncode(codeChallenge)}\">";
      formHtml = formHtml.Insert(formEndIndex, hiddenField);
      return true;
    }

    /// <summary>
    /// Appends the PKCE query params to an (internal) './authorize' url, so that the challenge
    /// will not get lost when redirecting back to the authorize page.
    /// </summary>
    internal static string AppendPkceQueryParams(string authorizeUrl, string codeChallenge) {
      if (string.IsNullOrEmpty(codeChallenge)) {
        return authorizeUrl;
      }
      return authorizeUrl.AppendQueryParam("code_challenge", codeChallenge, true).AppendQueryParam("code_challenge_method", _PkceMethodS256);
    }

  }

}
