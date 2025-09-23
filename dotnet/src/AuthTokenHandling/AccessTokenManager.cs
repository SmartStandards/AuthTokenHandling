//using System;
//using System.Collections.Generic;
//using System.ComponentModel.DataAnnotations;
//using System.Reflection;
//using System.Threading;


//TODO: DER HIER KOMMT ALS NÄCHSTES

//namespace Security.AccessTokenHandling {

//  public static class AccessTokenManager {


//    public static void SetupTokenSource(string tokenSourceUid, IAccessTokenIssuer issuer, IAccessTokenIntrospector introspector, params string[] urlBindings) {
   
    
//    }

//    public static void SetupTokenSource(string tokenSourceUid, AuthTokenConfig config, params string[] urlBindings) {


//    }

//    public static void BindUrlToTokenSource(string urlPattern, string tokenSourceUid) {



//    }

//    public static bool TryGetTokenSourceUidByUrl(string url, out string tokenSourceUid) {




//    }

//    public static bool TryEnsureActiveTokenForTargetUrl(string targetUrl, bool forceRefresh) {

//      if (TryGetTokenSourceUidByUrl(targetUrl, out string tokenSourceUid)) {
//        return TryEnsureActiveTokenForTokenSource(tokenSourceUid, forceRefresh);
//      }

//      return false;
//    }

//    public static bool TryEnsureActiveTokenForTokenSource(string tokenSourceUid, bool forceRefresh) {

//      if (forceRefresh) {
//        return TryGetActiveTokenForTokenSource(tokenSourceUid, forceRefresh, out string dummy);
//      }
//      else {
//        return false;
//      }

//    }

//    public static bool TryGetActiveTokenForTargetUrl(string targetUrl, bool forceRefresh, out string accessToken) {

//      if (TryGetTokenSourceUidByUrl(targetUrl, out string tokenSourceUid)) {
//        return TryGetActiveTokenForTokenSource(tokenSourceUid, forceRefresh, out accessToken);
//      }

//      accessToken = null;
//      return false;

//    }

//    public static bool TryGetActiveTokenForTokenSource(string tokenSourceUid, bool forceRefresh, out string accessToken) {


//      if (!forceRefresh) {
//        forceRefresh = !HasActiveToken(tokenSourceUid);
//      }

//      if (forceRefresh) {
//        //issuer bemühen


//      }
//      else {

//        //token zurück geben
//        return true;
//      }

//    }


//    public static bool HasActiveToken(string tokenSourceUid) {

//      //intrsocpetor aufrufen

//      NICHT ÜBER AccessTokenValidator, sodnern - DANN LIEBER EIGENES CACHING!!!
//        VOR ALLEM braucehn wir auch einen store für access,id,und refresh-token!!!!!

//        1x inmemory (AsyncLocal oder so)
//        1x persist (gpt fragen ob es einen sicheren soeicerot gibt
          
//          //KLARE TRENNUNG - DAUERHAFT SPEICHERN DÜRFEN WIR NUR RESFRSH-TOKENS - WEIL NUR DIE AUCH HIER GEISSUED WURDEN!!!!)
//          //WENN WIR EIN SERVER IND MuSS DAS AUCH  ÜBER SPEIZELLE OPT-IN STRAGIE GEHEN - DIE KANN IM CLIENT DANN AUCH OPT IN SEIN!!
//          //SAUBERES SCOPING VORAUSGESETZT


//    }


//    /////////////////////////////////////////////////////
//    // HOOKS


//    /// <summary>
//    /// Compatibile 'DefaultAuthHeaderGetter' for wire-up with 'UjmwClientConfiguration' (UJMW-Framework)
//    /// </summary>
//    /// <param name="contractType"></param>
//    /// <returns></returns>
//    public static string GetAuthHeaderByContractType(Type contractType) {


//      throw new NotImplementedException();
//      //kommt aus der verwender-welt  - ACHT DAS NOCH SINN MIT DEM CONTRACT-TYP!
      



//    }


//    /// <summary>
//    /// Compatibile 'RawTokenExposalMethod' for wire-up when calling 'AccessTokenManager.ConfigureTokenValidation'
//    /// </summary>
//    /// <param name="token"></param>
//    /// <param name="targetContractMethod"></param>
//    /// <param name="subject"></param>
//    /// <param name="permittedScopes"></param>
//    public static void PreserveIncommingToken(string token, MethodInfo targetContractMethod, string subject, string[] permittedScopes) {

//    }

//    /// <summary>
//    /// Compatibile 'IntrospectorLookupMethod' for wire-up when calling 'AccessTokenManager.ConfigureTokenValidation'
//    /// </summary>
//    /// <param name="tokenSourceIdentifier"></param>
//    /// <param name="contractType"></param>
//    /// <param name="targetContractMethod"></param>
//    /// <param name="callingMachine"></param>
//    /// <param name="tryReadJwtIssuerMethod"></param>
//    /// <returns></returns>
//    public static IAccessTokenIntrospector LookupForIntrospector(
//      string tokenSourceIdentifier,
//      Type contractType,
//      MethodInfo targetContractMethod,
//      string callingMachine,
//      Func<string> tryReadJwtIssuerMethod
//    ) {


//       throw new NotImplementedException();

//      //kommt aus der verwender-welt  - IST ZU AUFGEBLASEN!!!!!
   

//    }


//  }

//}
