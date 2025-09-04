
using Security.AccessTokenHandling.OAuthServer;

namespace Security.OAuth {

  /// <summary>
  /// Offizielle OAuth-/OIDC-Fehlercodes als String-Konstanten.
  /// Tipp: Nutze sie für Vergleiche auf error/error_description/error_uri Feldern.
  /// </summary>
  internal static class OAuthErrorPhrases {

    //TODO: konsequent hierauf umbauen!

    public static void SetError_InvalidRequest(this TokenIssuingResult extendee, string detailAppendix = null) {
      extendee.error = InvalidRequest;
      extendee.error_description = extendee.error;
      if (!string.IsNullOrWhiteSpace(detailAppendix)) {
        extendee.error_description = extendee.error_description + ": " + detailAppendix;
      }
    }

    // === RFC 6749 — Authorization Endpoint (Authz-Fehler) ===
    public const string InvalidRequest = "invalid_request";
    public const string UnauthorizedClient = "unauthorized_client";
    public const string AccessDenied = "access_denied";
    public const string UnsupportedResponseType = "unsupported_response_type";
    public const string InvalidScope = "invalid_scope";
    public const string ServerError = "server_error";
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    // === RFC 6749 — Token Endpoint (Token-Fehler) ===
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnsupportedGrantType = "unsupported_grant_type";

    // === RFC 6750 — Bearer Token (WWW-Authenticate) ===
    public const string InvalidToken = "invalid_token";
    public const string InsufficientScope = "insufficient_scope";
    // (invalid_request ist auch hier möglich, s. RFC 6750)

    // === RFC 7009 — Token Revocation ===
    public const string UnsupportedTokenType = "unsupported_token_type";

    // === RFC 8628 — Device Authorization Grant (Polling beim Token-Endpoint) ===
    public const string AuthorizationPending = "authorization_pending";
    public const string SlowDown = "slow_down";
    public const string ExpiredToken = "expired_token";
    // AccessDenied kann hier ebenfalls zurückkommen (siehe oben).

    // === RFC 7591 — Dynamic Client Registration ===
    public const string InvalidRedirectUri = "invalid_redirect_uri";
    public const string InvalidClientMetadata = "invalid_client_metadata";
    public const string InvalidSoftwareStatement = "invalid_software_statement";
    public const string UnapprovedSoftwareStatement = "unapproved_software_statement";

    // === OpenID Connect Core (Erweiterte Authz-Fehler) ===
    public const string InteractionRequired = "interaction_required";
    public const string LoginRequired = "login_required";
    public const string AccountSelectionRequired = "account_selection_required";
    public const string ConsentRequired = "consent_required";
    public const string InvalidRequestUri = "invalid_request_uri";
    public const string InvalidRequestObject = "invalid_request_object";
    public const string RequestNotSupported = "request_not_supported";
    public const string RequestUriNotSupported = "request_uri_not_supported";
    public const string RegistrationNotSupported = "registration_not_supported";

  }

}
