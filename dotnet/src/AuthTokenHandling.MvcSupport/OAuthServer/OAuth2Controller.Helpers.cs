using Logging.SmartStandards.CopyForAuthTokenHandling;
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
          SecLogger.LogWarning($"Cannot identify pass-trough user identity: Unknown identity-class");
        }
        SecLogger.LogInformation($"Identified pass-trough user identity: " + userName);
      }
      catch (Exception ex) {
        SecLogger.LogWarning($"Cannot identify pass-trough user identity: " + ex.Message);
      }

      return !string.IsNullOrWhiteSpace(userName);
    }

  }

  internal static class UrlHelperExtension {


    public static string SetQueryParam(this string url, string name, string value, bool urlEncode = false) {
      if (urlEncode || value.Contains("&")) {
        value = HttpUtility.UrlEncode(value);
      }
      if (url.Contains("?")) {
        int idx = url.IndexOf("?");
        string[] kvps = url.Substring(idx + 1).Split('&');
        for(int i=0; i<kvps.Length; i++) {
          string kvp = kvps[i];
          if (kvp.StartsWith($"{name}=")) {
            kvps[i] = $"{name}={value}";
            return $"{url.Substring(0, idx + 1)}{string.Join("&", kvps)}";
          }
        }
        return $"{url}&{name}={value}";
      }
      else {
        return $"{url}?{name}={value}";
      }
    }

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
