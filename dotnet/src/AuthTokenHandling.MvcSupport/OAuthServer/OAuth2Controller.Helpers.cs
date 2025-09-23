using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;

namespace Security.AccessTokenHandling.OAuth.Server {

  internal partial class OAuth2Controller {

    private bool TryGetPasstroughUserIdentity(out string userName) {
      userName = null;

      //if (!OperatingSystem.IsWindows()){
      //  return false;
      //}
 
      try {
        if (this.HttpContext.User.Identity is WindowsIdentity) {
          WindowsIdentity windowsUserIfIdentified = null;
          windowsUserIfIdentified = (WindowsIdentity)this.HttpContext.User.Identity!;
          userName = windowsUserIfIdentified.Name?.ToString();
        }
        else if (this.HttpContext.User.Identity is ClaimsIdentity) {
          ClaimsIdentity windowsUserIfIdentified = null;
          windowsUserIfIdentified = (ClaimsIdentity)this.HttpContext.User.Identity!;
          userName = windowsUserIfIdentified.Name?.ToString();
        }
        else {
          Trace.TraceWarning($"Cannot identify pass-trough user identity: Unknown identity-class");
        }
        Trace.TraceInformation($"Identified pass-trough user identity: " + userName);
      }
      catch (Exception ex) {
        Trace.TraceWarning($"Cannot identify pass-trough user identity: " + ex.Message);
      }

      return !string.IsNullOrWhiteSpace(userName);
    }

  }

  internal static class UrlHelperExtension {

    public static string AppendQueryParam(this string url, string name, string value, bool urlEncode = false) {
      if (urlEncode) {
        value = HttpUtility.UrlEncode(value);
      }
      if (url.Contains("?")) {
        return $"{url}&{name}={value}";
      }
      else {
        return $"{url}?{name}={value}";
      }
    }

  }

}
