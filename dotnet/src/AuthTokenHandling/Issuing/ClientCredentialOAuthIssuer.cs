using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling.OAuth {

  /******************************************************************

    DER HIER MACHT NORMALEN CLIENT CREDENTIAL FLOW

  /******************************************************************/

  public class ClientCredentialOAuthIssuer : IAccessTokenIssuer {

    private string _ClientId;
    private string _ClientSecret;

    private IOAuthOperationsProvider _OAuthOperationsProvider;
    private Action<ClaimApprovalContext> _ClaimApprovalHandler = null;

    public ClientCredentialOAuthIssuer(
      string clientId, string clientSecret, IOAuthOperationsProvider oAuthOperationsProvider, Action<ClaimApprovalContext> claimApprovalHandler = null
    ) {

      _ClientId = clientId;
      _ClientSecret = clientSecret;
      _OAuthOperationsProvider = oAuthOperationsProvider;
      _ClaimApprovalHandler = claimApprovalHandler;

    }

    bool IAccessTokenIssuer.TryRequestAccessToken(out TokenIssuingResult result) {
      return ((IAccessTokenIssuer)this).TryRequestAccessToken(null, out result);
    }

    bool IAccessTokenIssuer.TryRequestAccessToken(
      Dictionary<string, object> claimsToRequest, out TokenIssuingResult result
    ) {

      Dictionary<string, object> claimsToUse = ClaimApprovalContext.ProcessRequestedClaims(
        claimsToRequest, _ClaimApprovalHandler ?? ((c) => c.TakeOverAllRequestedClaims())
      );

      return _OAuthOperationsProvider.TryGetAccessTokenViaOAuthClientCredentials(_ClientId, _ClientSecret, out result, claimsToRequest);

    }

  }

}
