using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Web.UJMW;
using System.Windows.Forms;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling.TestApp")]

namespace AuthTokenHandling.TestApp {

  static class Program {

    /// <summary>
    ///  The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main() {

      Application.SetHighDpiMode(HighDpiMode.SystemAware);
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);




      //TODO: HIER VOLLES SETUP DES AccessTokenValidator

      //UjmwClientConfiguration.DefaultAuthHeaderGetter = AccessTokenManager.GetAuthHeaderByContractType;

      //UjmwClientConfiguration.RetryDecider = (Type contractType, Exception ex, int tryNumber, int httpCode, ref string url) => {
      //  if(tryNumber > 1) {
      //    return false;
      //  }
      //  if(httpCode == 401 || ex.Message.Contains("xpired")) {
      //    return AccessTokenManager.TryEnsureActiveTokenForTargetUrl(url, forceRefresh: true);
      //  }
      //  return (ex is TimeoutException || ex.Message.Contains("Timeout"));
      //};

      //AccessTokenValidator.ConfigureTokenValidation(
      //  new AuthReqzirementsprovicer,  //hier ansetzen -> ggf kann man da neben dem typ auch urln nutzen!!!!
      //  AccessTokenManager.LookupForIntrospector,
      //  (cfg) => {
      //    cfg.UseRawTokenExposal(AccessTokenManager.PreserveIncommingToken);
      //    cfg.ChangeCachingLifetime(0);//for the demo!
      //  }
      //);




      Application.Run(new FormMain());

    }

  }

}
