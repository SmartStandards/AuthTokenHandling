using CefSharp.DevTools.DOM;
using Newtonsoft.Json;
using Security.AccessTokenHandling;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AuthTokenHandling.TestApp {

  public partial class FormMain : Form {

    public FormMain() {
      this.InitializeComponent();

      this.FormClosing += this.FormMain_FormClosing;
      this.LoadFields();
    }

    private void FormMain_FormClosing(object sender, FormClosingEventArgs e) {
      this.SaveFields();
    }

    #region " Save/Load UI Inputs "

    private void LoadFields() {
      try {
        var decryptionMethod = (string encStr) => { return (new UTF8Encoding()).GetString(Convert.FromBase64String(Enumerable.Range(0, encStr.Length / 2).Select(i => encStr.Substring(i * 2, 2)).Select(x => (char)Convert.ToInt32(x, 16)).Aggregate(new StringBuilder(), (x, y) => x.Append(y)).ToString())); };
        string fileFullName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SmartStandards\\AuthTokenTestApp\\uistate.json");
        if (!File.Exists(fileFullName))
          return;
        string rawJson = System.IO.File.ReadAllText(fileFullName, System.Text.Encoding.UTF8);
        var fields = JsonConvert.DeserializeObject<Dictionary<string, object>>(rawJson);

        txtAuthorizeUrl.Text = (string)fields["authorizeUrl"];
        txtRedirectUrl.Text = (string)fields["redirectUrl"];
        txtGrantType.Text = (string)fields["grantType"];
        txtState.Text = (string)fields["state"];
        txtScopeToRequest.Text = (string)fields["scopeToRequest"];
        txtClientId.Text = decryptionMethod.Invoke((string)fields["clientId"]);
        txtClientSecret.Text = decryptionMethod.Invoke((string)fields["clientSecret"]);
        txtLoginHint.Text = (string)fields["loginHint"];
        txtRetrievalUrl.Text = (string)fields["retrievalUrl"];
        txtRetrievalCode.Text = (string)fields["retrievalCode"];
        cckUseHttpGetToRetrieve.Checked = (bool)fields["useHttpGetToRetrieve"];
        ///////////////////////////////////////////////////////
        txtIntrospectionUrl.Text = (string)fields["introspectionUrl"];
        ///////////////////////////////////////////////////////
        txtCurrentToken.Text = (string)fields["currentTokenRaw"];
        txtTokenContent.Text = (string)fields["currentTokenContent"];
      }
      catch {
      }
    }

    private void SaveFields() {
      try {
        var encryptionMethod = (string plaintext) => { return Convert.ToBase64String((new UTF8Encoding()).GetBytes(plaintext)).ToCharArray().Select(x => String.Format("{0:X}", (int)x)).Aggregate(new StringBuilder(), (x, y) => x.Append(y)).ToString(); };
        var fields = new Dictionary<string, object>();

        fields["authorizeUrl"] = txtAuthorizeUrl.Text;
        fields["redirectUrl"] = txtRedirectUrl.Text;
        fields["grantType"] = txtGrantType.Text;
        fields["state"] = txtState.Text;
        fields["scopeToRequest"] = txtScopeToRequest.Text;
        fields["clientId"] = encryptionMethod.Invoke(txtClientId.Text);
        fields["clientSecret"] = encryptionMethod.Invoke(txtClientSecret.Text);
        fields["loginHint"] = txtLoginHint.Text;
        fields["retrievalUrl"] = txtRetrievalUrl.Text;
        fields["retrievalCode"] = txtRetrievalCode.Text;
        fields["useHttpGetToRetrieve"] = cckUseHttpGetToRetrieve.Checked;
        ///////////////////////////////////////////////////////
        fields["introspectionUrl"] = txtIntrospectionUrl.Text;
        ///////////////////////////////////////////////////////
        fields["currentTokenRaw"] = txtCurrentToken.Text;
        fields["currentTokenContent"] = txtTokenContent.Text;

        string rawJson = JsonConvert.SerializeObject(fields, Formatting.Indented);
        string fileFullName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SmartStandards\\AuthTokenTestApp\\uistate.json");
        Directory.CreateDirectory(Path.GetDirectoryName(fileFullName));
        System.IO.File.WriteAllText(fileFullName, rawJson, System.Text.Encoding.UTF8);

      }
      catch {
      }
    }

    #endregion

    private void btnOpenLogonBrowser_Click(object sender, EventArgs e) {
      this.SaveFields();
      try {

        var client = new OAuthTokenRequestor(
          txtClientId.Text, txtClientSecret.Text, txtAuthorizeUrl.Text, txtRetrievalUrl.Text
        );

        if(txtGrantType.Text == "code") {
          txtRetrievalCode.Text = "";

          client.TryBrowserAuthViaCodeGrand(
            this, txtRedirectUrl.Text, txtState.Text, txtScopeToRequest.Text, txtLoginHint.Text,
            out string code, 800, 700, "Logon-Window (Browser)"
          );

          txtRetrievalCode.Text = code;
        }
        else {
          txtRetrievalCode.Text = "";
          txtCurrentToken.Text = "";
          txtCurrentRefreshToken.Text = "";
          txtCurrentIdToken.Text = "";

          client.TryBrowserAuthViaImplicitGrand(
            this, txtRedirectUrl.Text, txtState.Text, txtScopeToRequest.Text, txtLoginHint.Text,
            out string accessToken, out string refreshToken, out string idToken,
            800, 700, "Logon-Window (Browser)"
          );

          txtCurrentToken.Text = accessToken;
          txtCurrentRefreshToken.Text = refreshToken;
          txtCurrentIdToken.Text = idToken;
        }
      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void btlSilent_Click(object sender, EventArgs e) {
      this.SaveFields();
      try {

        var client = new OAuthTokenRequestor(
          txtClientId.Text, txtClientSecret.Text, txtAuthorizeUrl.Text, txtRetrievalUrl.Text
        );

        if (client.TrySilentAuthViaCodeGrand(
          txtRedirectUrl.Text, txtState.Text, txtScopeToRequest.Text, txtLoginHint.Text, out string code
        )) {
          txtRetrievalCode.Text = code;
        }
        else {
          txtRetrievalCode.Text = string.Empty;
        }
      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void btnRetrieveToken_Click(object sender, EventArgs e) {
      this.SaveFields();
      try {
        var client = new OAuthTokenRequestor(
          txtClientId.Text, txtClientSecret.Text, txtAuthorizeUrl.Text, txtRetrievalUrl.Text, txtRedirectUrl.Text
        );

        if (client.TryRetrieveTokenViaCode(txtRetrievalCode.Text, this.cckUseHttpGetToRetrieve.Checked,
          out string token, out string refresh, out string id, out string error)) {
          txtCurrentToken.Text = token;
          txtCurrentRefreshToken.Text = refresh;
          txtCurrentIdToken.Text = id;
        }
        else {
          txtCurrentToken.Text = string.Empty;
          txtCurrentRefreshToken.Text = string.Empty;
          txtCurrentIdToken.Text = string.Empty;
          MessageBox.Show(this, error, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        this.SaveFields();
      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void btnIntrospect_Click(object sender, EventArgs e) {
      this.SaveFields();
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
        this.SaveFields();
      }
      catch (Exception ex) {
        MessageBox.Show(this, ex.Message, "EXCEPTION", MessageBoxButtons.OK, MessageBoxIcon.Error);
      }
    }

    private void txtTokenContent_TextChanged(object sender, EventArgs e) {
      txtTokenState.Text = string.Empty;
    }

    private void button1_Click(object sender, EventArgs e) {

    }

    private void FormMain_Load(object sender, EventArgs e) {

    }

    private void txtIntrospectionUrl_TextChanged(object sender, EventArgs e) {

    }

  }
}
