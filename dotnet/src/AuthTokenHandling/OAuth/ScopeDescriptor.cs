using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Security.AccessTokenHandling.OAuth {

  [DebuggerDisplay("{Expression}")]
  public class ScopeDescriptor {
    public string Expression { get; set; }
    public string Label { get; set; }
    public bool Selected { get; set; }
    public bool ReadOnly { get; set; }
    public bool Invisible { get; set; }
  }

  public static class ScopeDescriptorExtensions {

    public static string[] ToStringArray(this ScopeDescriptor[] scopes) {
      return scopes.Where((s) => s.Selected).Select((s) => s.Expression).ToArray();
    }

  }

  //public class EnvironmentUiCustomizing {
  //  public string AuthPageTitle { get; set; } = "OAuth Logon";
  //  public string AuthPageLogonText { get; set; } = "Please enter your credentials:";
  //  public string AuthPageLogoImage { get; set; } = "";
  //  public string AuthPageBgColor { get; set; } = "#0ca3d2";
  //  public string PortalUrl { get; set; } = "";
  //  public string LegalUrl { get; set; } = "";
  //}

}
