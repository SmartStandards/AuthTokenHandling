using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AuthTokenHandling.TestApp {
  public partial class FormMain : Form {

    public FormMain() {
      this.InitializeComponent();
    }

    private void button3_Click(object sender, EventArgs e) {

      using (var dlg = new BrowserForm()) {
        dlg.Url = $"{txtAuthorizeUrl.Text}?redirect_uri={txtRedirectUrl.Text}&state={txtState.Text}&scope={txtScopeToRequest.Text}&login_hint={txtLoginHint.Text}&client_id={txtClientId.Text}";
        dlg.ReturnOn = txtRedirectUrl.Text;
        dlg.ShowDialog(this);
        string code = null;
        if (dlg.Url.StartsWith(txtRedirectUrl.Text, StringComparison.InvariantCultureIgnoreCase)) {
          code = (
            (dlg.Url + "?").
            Split('?')[1].
            Split('&').
            Where((x) => x.StartsWith("code=", StringComparison.CurrentCultureIgnoreCase)).
            Select((x) => x.Substring(x.IndexOf("=") + 1)).
            FirstOrDefault()
          );

        }
        if (string.IsNullOrWhiteSpace(code)) {
          txtRetrievalCode.Text = string.Empty;
        }
        else {
          txtRetrievalCode.Text = code;
        }
      }

    }


  }
}
