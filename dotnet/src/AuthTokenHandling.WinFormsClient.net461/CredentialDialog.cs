using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Security.AccessTokenHandling {

  internal partial class CredentialDialog : Form {

    public static bool AskUserForCredentials(
      string logonNameInputLabel,
      string logonNameSyntaxRegex,
      string logonPassInputLabel,
      bool logonNameAvailable,
      bool persistNameCheckVisible,
      ref bool persistNameChecked,
      string errorMessageToDisplay,
      ref string logonName,
      ref byte[] logonPass
      ) {

      using (CredentialDialog dlg = new CredentialDialog()) {

        //TODO: mainfprom als parent aus static variable holen!!!!
        dlg.ShowDialog();



        throw new NotImplementedException();

      }
    }

    private CredentialDialog() {
    
      //this.SuspendLayout();
      
      this.InitializeComponent();
      
      
 
    }

  }

}
