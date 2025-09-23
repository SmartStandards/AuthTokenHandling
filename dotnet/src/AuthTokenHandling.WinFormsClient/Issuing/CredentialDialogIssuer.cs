using Logging.SmartStandards;
using Newtonsoft.Json.Linq;
using Security.AccessTokenHandling;
using Security.AccessTokenHandling.OAuth;
using Security.AccessTokenHandling.SecretPersistation;
using System;
using System.CodeDom;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static Security.AccessTokenHandling.InteractiveCredentialDialogIssuer;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// INTERACTIVE-ISSUER!
  /// Wrapper that requests credentials via dialog and forwards them as claims into a non-interactive issuer
  /// </summary>
  public class InteractiveCredentialDialogIssuer : IAccessTokenIssuer {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="claimName"></param>
    /// <param name="displayLabel"></param>
    /// <param name="isHiddenInput"></param>
    /// <param name="encryptVia">use this to encrypt or has the given input before passing it to anyone!</param>
    /// <param name="isOptional"></param>
    /// <param name="defaultValue"></param>
    /// <param name="allowPersist"></param>
    /// <param name="forFactoryOnly"></param>
    public delegate void UserPromtRegistrationDelegate(
      string claimName, string displayLabel,
      bool isHiddenInput = false,
      Func<string, string> encryptVia = null,
      bool isOptional = false,
      object defaultValue = null,
      bool allowPersist = true,
      bool forFactoryOnly = false
    );

    public delegate void UserPromtSetupDelegate(
      UserPromtRegistrationDelegate promt
    );

    public delegate IAccessTokenIssuer NonInteractiveIssuerFactoryDelegate(
      Dictionary<string, object> userInput
    );

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    private List<PromtDefinition> _RegisteredPromts = new List<PromtDefinition>();
    private NonInteractiveIssuerFactoryDelegate _NonInteractiveIssuerFactory = null;
    private IAccessTokenIssuer _FixedInstanxceOfAccessTokenIssuer = null;
    private IWin32Window _ParentWindow = null;
    private Action<ClaimApprovalContext> _ClaimApprovalHandler = null;

    public Func<string> PersistationScopeDiscriminatorGetter { get; set; } = null;
    public ISecretStore PersistVia { get; set; } = null;

    public InteractiveCredentialDialogIssuer(
      UserPromtSetupDelegate userPromtSetup,
      IAccessTokenIssuer nonInteractiveIssuer,
      IWin32Window parentWindow = null,
      Action<ClaimApprovalContext> claimApprovalHandler = null
    ) : this(userPromtSetup, (userInput) => null, parentWindow, claimApprovalHandler) {
      _FixedInstanxceOfAccessTokenIssuer = nonInteractiveIssuer;
    }

    public InteractiveCredentialDialogIssuer(
      UserPromtSetupDelegate userPromtSetup,
      NonInteractiveIssuerFactoryDelegate nonInteractiveIssuerFactory,
      IWin32Window parentWindow = null,
      Action<ClaimApprovalContext> claimApprovalHandler = null
    ) {

      _ClaimApprovalHandler = claimApprovalHandler;

      userPromtSetup.Invoke((claimName, displayLabel, isHiddenInput, encryptVia, isOptional, defaultValue, allowPersist, forFactoryOnly) => {
      
        if(isHiddenInput && !forFactoryOnly && (encryptVia == null)) {
          throw new ArgumentException(
            "For hidden inputs (A) a valid encryption method must be provided, which must not return the input content" +
            "OR (B) they must be registred as forFactoryOnly=true, to be available just when invokig the 'nonInteractiveIssuerFactory'!"
          ) ;
        }

        _RegisteredPromts.Add(new PromtDefinition() {
          ClaimName = claimName,
          DisplayLabel = displayLabel,
          IsHiddenInput = isHiddenInput,
          EncryptVia = encryptVia,
          IsOptional = isOptional,
          DefaultValue = defaultValue,
          AllowPersist = allowPersist,
          ForFactoryOnly = forFactoryOnly
        });
      });

      _NonInteractiveIssuerFactory = nonInteractiveIssuerFactory ?? 
        throw new ArgumentNullException(nameof(nonInteractiveIssuerFactory));

      _ParentWindow = parentWindow;
    }

    /// <summary>
    /// Just a convenience for a quick setup of registry-based secret persistation
    /// with a little out-of-the-box security...
    /// </summary>
    /// <param name="explicitScopeName"></param>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public void EnableRegistryPersistation(string explicitScopeName = null) {
      Assembly caller = Assembly.GetCallingAssembly();
      string callerScope;
      string key;
      using (MD5 md5 = MD5.Create()) {
        callerScope = Convert.ToBase64String(md5.ComputeHash(Encoding.Default.GetBytes(caller.Location + caller.FullName)));
        key = Convert.ToBase64String(md5.ComputeHash(Encoding.Default.GetBytes(callerScope + caller.FullName)));
      }
      if (explicitScopeName != null) {
        this.PersistationScopeDiscriminatorGetter = (() => explicitScopeName);
      }
      if (this.PersistationScopeDiscriminatorGetter == null) {
        this.PersistationScopeDiscriminatorGetter = (() => callerScope);
      }
      this.PersistVia = new UserRegistrySecretStore(key);
    }

    public bool TryRequestAccessToken(out TokenIssuingResult accessToken) {
      return ((IAccessTokenIssuer)this).TryRequestAccessToken(null, out accessToken);
    }

    public bool TryRequestAccessToken(
      Dictionary<string, object> claimsToRequest, out TokenIssuingResult result
    ) {

      using (CredentialDialog dialog = new CredentialDialog()) {

        foreach (PromtDefinition promt in _RegisteredPromts) {
          dialog.RegisterPromt(promt.ClaimName, promt.DisplayLabel, promt.IsHiddenInput, promt.IsOptional, promt.DefaultValue);
        }

        dialog.ClaimsToEdit = claimsToRequest;

        if(this.PersistVia != null) {
          string scope = this.PersistationScopeDiscriminatorGetter.Invoke();
          foreach (PromtDefinition promt in _RegisteredPromts) {
            if (promt.AllowPersist) {
              if (this.PersistVia.TryLoadSecret(scope, promt.ClaimName, out string value)) {
                dialog.SetRawInput(promt.ClaimName, value);
              }
            }
          }
        }

        result = new TokenIssuingResult();
        result.error = "user_abort";
        result.error_description = "The user aborted the credential input dialog.";

        DialogResult dialogResult = DialogResult.None;
        while (dialogResult != DialogResult.Cancel) {
          
          if (_ParentWindow != null) {
            dialogResult = dialog.ShowDialog(_ParentWindow);
          }
          else {
            dialogResult = dialog.ShowDialog(_ParentWindow);
          }

          bool issuingResult = false;
          if (dialogResult == DialogResult.OK) {

            Dictionary<string, object> claimsAfterEncryption = ClaimApprovalContext.ProcessRequestedClaims(
              dialog.ClaimsToEdit,
              (claims) => {
                foreach (PromtDefinition promt in _RegisteredPromts) {
                  if(promt.EncryptVia != null) {
                    claims.TryMapRequestedClaim(promt.ClaimName, promt.ClaimName, (v) => promt.EncryptVia(v?.ToString()));
                  }
                  else {
                    claims.TakeOverRequestedClaims(promt.ClaimName);
                  }
                }
              }
            );

            Dictionary<string, object> filteredClaimsToUse = ClaimApprovalContext.ProcessRequestedClaims(
               claimsAfterEncryption,
               _ClaimApprovalHandler ?? ((c) => c.TakeOverAllRequestedClaims()), // << here comes the external customizing...
               (claims) => { 
                 foreach (PromtDefinition promt in _RegisteredPromts) {
                   if (promt.ForFactoryOnly) { //but this one counts harder!
                     claims.RemoveFromClaimsToUseIfPresent(promt.ClaimName);
                   }
                 }
               }
            );

            if (_FixedInstanxceOfAccessTokenIssuer != null) {
              issuingResult = _FixedInstanxceOfAccessTokenIssuer.TryRequestAccessToken(filteredClaimsToUse, out result);
            }
            else {
              IAccessTokenIssuer tempIssuerInstance = null;
              try {
                tempIssuerInstance = _NonInteractiveIssuerFactory.Invoke(claimsAfterEncryption);//<< yes the unfiltered one!
                issuingResult = tempIssuerInstance.TryRequestAccessToken(filteredClaimsToUse, out result);
              }
              finally {
                if (tempIssuerInstance != null && tempIssuerInstance is IDisposable) {
                  (tempIssuerInstance as IDisposable).Dispose();
                }
              }     
            }

            if (issuingResult) {

              if (this.PersistVia != null) {
                string scope = this.PersistationScopeDiscriminatorGetter.Invoke();
                foreach (PromtDefinition promt in _RegisteredPromts) {
                  if (promt.AllowPersist) {
                    this.PersistVia.SaveSecret(scope, promt.ClaimName, dialog.GetRawInput(promt.ClaimName));
                  }
                }
              }

              return true;
            }
            else {

              if (string.IsNullOrEmpty(result.error)) {
                result.error = "issuer_failed";
              }
              if (string.IsNullOrEmpty(result.error_description)) {
                result.error_description = result.error;
              }

              dialog.DisplayError(result.error_description);
            }

          }

        }

        return false;
      } 
    
    }

    private class PromtDefinition {
      public string ClaimName { get; set; }
      public string DisplayLabel { get; set; }
      public bool IsHiddenInput { get; set; }
      public bool IsOptional { get; set; }
      public object DefaultValue { get; set; }
      public bool AllowPersist { get; set; }
      public Func<string, string> EncryptVia { get; set; }
      public bool ForFactoryOnly { get; set; }
    }

  }

}
