using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

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

      this.webView.CreationProperties = new CoreWebView2CreationProperties();
      this.webView.CreationProperties.UserDataFolder = GetUserDataFolder();
      this.webView.CoreWebView2InitializationCompleted += this.WebView_CoreWebView2InitializationCompleted;
    }

    /// <summary>
    /// Returns a user-writable folder for the WebView2 profile data (cookies, cache, ...),
    /// because the default location (next to the executable) is not always writable.
    /// </summary>
    private static string GetUserDataFolder() {

      string folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SmartStandards", "AuthTokenHandling", "WebView2"
      );

      Directory.CreateDirectory(folder);

      return folder;
    }

    private void TxtUrl_KeyDown(object sender, KeyEventArgs e) {

      if (this.webView.CoreWebView2 == null) {
        return;
      }

      if (e.KeyCode == Keys.Return || e.KeyCode == Keys.F5) {
        this.webView.CoreWebView2.Reload();
      }
      if (e.KeyCode == Keys.Back) {
        this.webView.CoreWebView2.Navigate(_EntryUrl);
      }
      if (e.KeyCode == Keys.F12) {
        this.webView.CoreWebView2.OpenDevToolsWindow();
      }

    }

    private void BrowserForm_Shown(object sender, EventArgs e) {

      this.webView.Dock = DockStyle.Fill;
      this.webView.Visible = true;
      this.webView.BringToFront();

      // setting the 'Source' implicitly initializes the WebView2 environment (using the 'CreationProperties')
      this.webView.Source = new Uri(txtUrl.Text);

      timer1.Enabled = true;
      this.ResumeLayout();
    }

    private void WebView_CoreWebView2InitializationCompleted(object sender, CoreWebView2InitializationCompletedEventArgs e) {

      if (!e.IsSuccess) {
        return;
      }

      this.webView.CoreWebView2.NavigationStarting += this.CoreWebView2_NavigationStarting;
    }

    private void CoreWebView2_NavigationStarting(object sender, CoreWebView2NavigationStartingEventArgs e) {

      // the redirect target (usually a dummy uri) does not need to be loaded,
      // so we are intercepting the navigation as soon as the final url is known
      if (this.IsReturnUrl(e.Uri)) {
        e.Cancel = true;
        txtUrl.Text = e.Uri;
        timer1.Enabled = false;
        this.Close();
      }

    }

    private bool IsReturnUrl(string url) {

      if (string.IsNullOrWhiteSpace(url)) {
        return false;
      }

      return (
        url.StartsWith(this.ReturnOn, StringComparison.InvariantCultureIgnoreCase) &&
        url.ToLower().Contains("code=")
      );
    }

    private string _EntryUrl = "";

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public String CurrentUrl {
      get {
        return this.txtUrl.Text;
      }
      set {
        _EntryUrl = value;
        this.txtUrl.Text = value;
      }
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public String ReturnOn { get; set; } = "DUMMY";

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Visible)]
    public int SecondsToWaitBeforeShowing { get; internal set; }

    private void BrowserForm_FormClosed(object sender, FormClosedEventArgs e) {

      timer1.Enabled = false;

      if (this.webView.CoreWebView2 != null) {
        this.webView.CoreWebView2.NavigationStarting -= this.CoreWebView2_NavigationStarting;
      }

    }

    private void Timer1_Tick(object sender, EventArgs e) {

      if (this.Opacity == 0) {
        this.Opacity = 1;
      }

      if (this.webView.Source == null) {
        return;
      }

      txtUrl.Text = this.webView.Source.ToString();

      if (this.IsReturnUrl(txtUrl.Text)) {
        timer1.Enabled = false;
        this.Close();
      }

    }

    private void txtUrl_TextChanged(object sender, EventArgs e) {
    }

    private void BrowserForm_Load(object sender, EventArgs e) {

    }

  }

}
