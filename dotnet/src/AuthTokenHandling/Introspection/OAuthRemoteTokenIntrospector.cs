using Security.AccessTokenHandling.OAuth;
using System;
using System.Collections.Generic;

namespace Security.AccessTokenHandling {

  public class OAuthRemoteTokenIntrospector : IAccessTokenIntrospector {

    private IOAuthOperationsProvider _OAuthOperationsProvider;

    public OAuthRemoteTokenIntrospector(IOAuthOperationsProvider oAuthOperationsProvider) {
      _OAuthOperationsProvider = oAuthOperationsProvider;
    }

    public void IntrospectAccessToken(
      string rawToken, out bool isActive, out Dictionary<string, object> claims
    ) {

      bool success = _OAuthOperationsProvider.TryValidateToken(
        rawToken, out isActive, out DateTime? validUntil, out string invalidReason
      );

      success = success & _OAuthOperationsProvider.TryResolveSubjectAndScopes(
        rawToken,
        out string subject,
        out string[] scopes,
        out claims
      );

    }

  }

}

