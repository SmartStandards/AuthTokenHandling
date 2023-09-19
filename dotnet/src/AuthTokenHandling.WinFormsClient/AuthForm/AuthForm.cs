using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CefSharp.WinForms;
using CefSharp;

namespace Security.AccessTokenHandling {

  internal partial class AuthForm : Form {

    public AuthForm() {
      this.SuspendLayout();
      this.InitializeComponent();
      this.Shown += this.BrowserForm_Shown;
      this.FormClosed += this.BrowserForm_FormClosed;
      this.timer1.Tick += this.Timer1_Tick;
      this.Opacity = 0;
      this.BackColor = Color.White;

      this.txtUrl.KeyDown += this.TxtUrl_KeyDown;
    }

    private void TxtUrl_KeyDown(object sender, KeyEventArgs e) {
      if (e.KeyCode == Keys.Return || e.KeyCode == Keys.F5) {
        this.chromiumWebBrowser1.Load(this.chromiumWebBrowser1.GetMainFrame().Url);
      }
      if (e.KeyCode == Keys.Back) {
        this.chromiumWebBrowser1.Load(_EntryUrl);
      }
      if (e.KeyCode == Keys.F12) {
        this.chromiumWebBrowser1.ShowDevTools();
      }
    }

    private ChromiumWebBrowser _CefBrowser;

    private bool subscribed = false;

    private void BrowserForm_Shown(object sender, EventArgs e) {

      this.chromiumWebBrowser1.Dock = DockStyle.Fill;
      this.chromiumWebBrowser1.Visible = true;
      this.chromiumWebBrowser1.Show();
      this.chromiumWebBrowser1.LoadUrl(txtUrl.Text);

      if (!subscribed) {
        //this.chromiumWebBrowser1.LocationChanged += this.ChromiumWebBrowser1_LocationChanged;
        subscribed = true;
      }

      timer1.Enabled = true;
      this.ResumeLayout();
    }

    private string _EntryUrl = "";
    public String Url {
      get {
        return this.txtUrl.Text;
      }
      set {
        _EntryUrl = value;
        this.txtUrl.Text = value;
      }
    }
    public String ReturnOn { get; set; } = "DUMMY";

    private void BrowserForm_FormClosed(object sender, FormClosedEventArgs e) {
      if (subscribed) {
        //this.chromiumWebBrowser1.LocationChanged += this.ChromiumWebBrowser1_LocationChanged;
        subscribed = false;
      }
      timer1.Enabled = false;
    }

    private void Timer1_Tick(object sender, EventArgs e) {
      if (this.chromiumWebBrowser1.IsBrowserInitialized) {

        if (this.Opacity == 0) {
          this.Opacity = 1;
        }

        txtUrl.Text = this.chromiumWebBrowser1.GetBrowser().MainFrame.Url;

        if (txtUrl.Text.StartsWith(
          this.ReturnOn, StringComparison.InvariantCultureIgnoreCase) &&
          txtUrl.Text.ToLower().Contains("code=")
        ) {
          this.Close();
        }

      }
    }

    private void txtUrl_TextChanged(object sender, EventArgs e) {
    }

    private void BrowserForm_Load(object sender, EventArgs e) {

    }
  }

}
