using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// This is a facade to encapsulate an hook, than can be initialized
  /// when the current appdomain having capabilities to request logon information
  /// from the interacting user synchronously (for example using a WinForms popup dialog)
  /// </summary>
  public static class InteractiveCredentialRequestor {

    /// <summary>
    /// returns true on OK or false on cancel
    /// </summary>
    /// <returns></returns>
    public delegate bool AskUserForCredentialsDelegate(
      string logonNameInputLabel,
      string logonNameSyntaxRegex,
      string logonPassInputLabel,
      bool logonNameAvailable,
      bool persistNameCheckVisible,
      bool persistNameChecked,
      string errorMessageToDisplay,
      ref string logonName, ref byte[] logonPass
    );

    private static AskUserForCredentialsDelegate _OnAskUserForCredentials = null;

    private static string _LogonNameInputLabel;
    private static string _LogonNameSyntaxRegex;
    private static string _LogonPassInputLabel;
    private static string _PersistNameCheckVisible;
    private static string _PersistNameChecked;

    public static void Setup(AskUserForCredentialsDelegate requestorMethod, AuthTokenConfig configurationDetails) {
      configurationDetails.LocalLogonNameInputLabel
      configurationDetails.LocalLogonNameSyntax

        configurationDetails.LocalLogonPassInputLabel
        configurationDetails.LocalLogonNamePersistation
 configurationDetails.LocalLogonNameToLower
        LocalLogonSaltDisplayLabel
    }
    public static void Setup(AskUserForCredentialsDelegate requestorMethod) {




    }

    /// <summary>
    /// This method is compatible to be used as 'ClaimCustomizerDelegate'.
    /// It can be wired-up directly to the LocalJwtIssuer
    /// </summary>
    /// <param name="requestedClaims"></param>
    /// <param name="claimsToUse"></param>
    /// <param name="mergeRequestedClaims"></param>
    public static void ExtendClaimsWithuserInput(
       Dictionary<string, object> requestedClaims,
       Dictionary<string, object> claimsToUse,
       ref bool mergeRequestedClaims
    ) {

      if (_OnAskUserForCredentials == null) {


      }
      else {


      }

    }

  }

}
