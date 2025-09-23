using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling")]

namespace Security.AccessTokenHandling.OAuth.Server {

  //INFO: liegt bewusst in 'AuthTokenHandling' anstatt 'AuthTokenHandling.MvcSupport',
  //weil die serverseitige Implementierung wahrscheinlich nicht im MVC Serviceprojekt, sondern in einer
  //technologieunabhängigen Assembly leben wird. Letzterer wollen wir keine sub-Referenzen auf MVC Artefakte 
  //aufzwingen, nur weil sie dieses Interface addressieren muss. Wenn überhaupt, müsste dieses Interface
  //in eine ebenfalls technologieunabhängigen 'AuthTokenHandling.Server' assembly (wäre aktuell aber oversized)

  public interface IOAuthService : IAccessTokenIntrospector {

    /// <summary>
    /// should return a sessionOtp
    /// </summary>
    /// <param name="apiClientId"></param>
    /// <param name="login"></param>
    /// <param name="password"> is empty when noPasswordNeeded</param>
    /// <param name="noPasswordNeeded"> is true when windows pass-trough has already been processed</param>
    /// <param name="clientProvidedState"></param>
    /// <param name="sessionId"></param>
    /// <param name="message"></param>
    /// <returns></returns>
    bool TryAuthenticate(
      string apiClientId,
      string login,
      string password,
      bool noPasswordNeeded,
      string clientProvidedState,
      out string sessionId,
      out string message
    );

    bool TryGetAvailableScopesBySessionId(
      string apiClientId,
      string sessionId,
      string[] prefferedScopes,
      out ScopeDescriptor[] availableScopes,
      out string message
    );

    TokenIssuingResult ValidateClientAndCreateToken(
      string clientId, string clientSecret, string[] selectedScopes
    );

    bool TryValidateSessionIdAndCreateToken(
      string apiClientId, string sessionId, string[] selectedScopes,
      out TokenIssuingResult tokenResult
    );

    bool TryValidateSessionIdAndCreateRetrievalCode(
      string apiClientId, string sessionId, string[] selectedScopes,
      out string code, out string message
    );

    TokenIssuingResult RetrieveTokenByCode(
      string clientId, string clientSecret, string code
    );

    bool TryValidateApiClient(
      string apiClientId,
      string apiCallerHost,
      string redirectUri,
      out string message
    );

    TokenIssuingResult CreateFollowUpToken(
      string refreshToken
    );
  }

  public interface IOAuthServiceWithDelegation : IOAuthService {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="loginHint"></param>
    /// <param name="targetAuthorizeUrl"></param>
    /// <param name="targetClientId"></param>
    /// <param name="anonymousSessionId">
    /// A valid sessionId, but without any relation to a user-identity
    /// (because we wont have any subject-identity before returning from the delegate).
    /// Instead this sessionId needs to hold neccesarry information to identify the delegation target
    /// and to be able to retrieve the token when only having the code (after returning).
    /// </param>
    /// <returns></returns>
    bool CodeFlowDelegationRequired(
      string clientId, ref string loginHint, out string targetAuthorizeUrl, out string targetClientId, out string anonymousSessionId
    );

    /// <summary>
    /// IMPORTANT: after retrieving the token, this method must also identify the subject 
    /// and impersonate the sessionId to the now discovered user-identity
    /// (otherwiese the scopes cannot be evauated)
    /// </summary>
    /// <param name="codeFromDelegate"></param>
    /// <param name="sessionId">The sessionId was transferred trough the whole external flow inside of the 'state'</param>
    /// <param name="thisRedirectUri">
    /// In some cases the initial redirect_uri needs to be provided also when retriving the token.
    /// Because of inversion of control the server logic must not know the exact url (its the job of the controller) - 
    /// so we will provide it on demand, comming directly from the incomming http-request...
    /// </param>
    /// <returns></returns>
    bool TryHandleCodeflowDelegationResult(
      string codeFromDelegate, string sessionId, string thisRedirectUri
    );

  }

}
