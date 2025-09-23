//using Security.AccessTokenHandling;
//using Security.AccessTokenHandling.OAuth;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net;
//using System.Net.Http;
//using System.Net.Sockets;
//using System.Reflection;
//using System.Security.Claims;
//using System.Threading.Tasks;

//namespace Security.AccessTokenHandling.OAuth {

//  /******************************************************************

//    DER HIER MACHT EINEN LOKALEN PORT AUF, STARTET DEN STANDAD-BROWSER


//  signaturen (cosntruktor kopieren vom embedded)
//  /******************************************************************/

//  /// <summary>
//  /// INTERACTIVE-ISSUER!
//  /// </summary>
//  public class ExternalBrowserOAuthIssuer : IAccessTokenIssuer {

//    public ExternalBrowserOAuthIssuer(  , Action<ClaimApprovalContext> claimApprovalHandler = null) { 
    
//    }

//    bool IAccessTokenIssuer.TryRequestAccessToken(out TokenIssuingResult accessToken) {
//      return ((IAccessTokenIssuer)this).TryRequestAccessToken(null, out accessToken);
//    }

//    bool IAccessTokenIssuer.TryRequestAccessToken(
//      Dictionary<string, object> claimsToRequest, out TokenIssuingResult accessToken
//    ) {



  //TODO: entwurf bereits vorhanden - muss hier noch rein!







//    }

//  }

//}
