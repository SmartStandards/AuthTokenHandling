using Newtonsoft.Json;
using Security.AccessTokenHandling;
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

    private void btnOpenLogonBrowser_Click(object sender, EventArgs e) {
      try {

        var client = new OAuthTokenRequestor(
          txtClientId.Text, txtClientSecret.Text, txtAuthorizeUrl.Text, txtRetrievalUrl.Text
        );

        client.TryBrowserAuthViaCodeGrand(
          this, txtRedirectUrl.Text, txtState.Text, txtScopeToRequest.Text, txtLoginHint.Text, out string code, 800, 600, "Logon-Window (Browser)"
        );
        txtRetrievalCode.Text = code;

      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void btnRetrieveToken_Click(object sender, EventArgs e) {
      try {
        var client = new OAuthTokenRequestor(
          txtClientId.Text, txtClientSecret.Text, txtAuthorizeUrl.Text, txtRetrievalUrl.Text
        );

        if (client.TryRetrieveTokenViaCode(txtRetrievalCode.Text, out string token)) {
          txtCurrentToken.Text = token;
        }
        else {
          txtCurrentToken.Text = string.Empty;
        }
      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void btnIntrospect_Click(object sender, EventArgs e) {
      try {

        var client = new OAuthTokenIntrospectionEndpointCaller(
          txtIntrospectionUrl.Text
        );

        client.IntrospectAccessToken(txtCurrentToken.Text, out bool active, out var claims);

        if (claims != null) {
          txtTokenContent.Text = JsonConvert.SerializeObject(claims, Formatting.Indented);
        }
        else {
          txtTokenContent.Text = "";
        }

        if (active) {
          txtTokenState.Text = "VALID";
          txtTokenState.ForeColor = Color.DarkGreen;
        }
        else {
          txtTokenState.Text = "INVALID";
          txtTokenState.ForeColor = Color.Red;
        }

      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void txtTokenContent_TextChanged(object sender, EventArgs e) {
      txtTokenState.Text = string.Empty;
    }

  }
}
