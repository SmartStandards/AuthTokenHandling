using System.Windows.Forms;

namespace Security.AccessTokenHandling {

  partial class AuthForm {
    /// <summary>
    /// Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    /// Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
    protected override void Dispose(bool disposing) {
      if (disposing && (components != null)) {
        components.Dispose();
      }
      base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    /// Required method for Designer support - do not modify
    /// the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent() {
      components = new System.ComponentModel.Container();
      System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AuthForm));
      timer1 = new Timer(components);
      txtUrl = new TextBox();
      this.SuspendLayout();
      // 
      // timer1
      // 
      timer1.Interval = 1000;
      // 
      // txtUrl
      // 
      txtUrl.BackColor = System.Drawing.SystemColors.Window;
      txtUrl.Dock = DockStyle.Top;
      txtUrl.Font = new System.Drawing.Font("Consolas", 7F);
      txtUrl.Location = new System.Drawing.Point(0, 0);
      txtUrl.Name = "txtUrl";
      txtUrl.ReadOnly = true;
      txtUrl.Size = new System.Drawing.Size(800, 18);
      txtUrl.TabIndex = 1;
      txtUrl.Text = "https://www.google.de";
      txtUrl.TextChanged += this.txtUrl_TextChanged;
      // 
      // AuthForm
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
      this.AutoScaleMode = AutoScaleMode.Font;
      this.BackColor = System.Drawing.Color.White;
      this.ClientSize = new System.Drawing.Size(800, 450);
      this.Controls.Add(txtUrl);
      this.Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
      this.Name = "AuthForm";
      this.Text = "Logon-Window (Browser)";
      this.Load += this.BrowserForm_Load;
      this.ResumeLayout(false);
      this.PerformLayout();
    }

    #endregion

    private CefControl chromiumWebBrowser1;
    private System.Windows.Forms.Timer timer1;
    private System.Windows.Forms.TextBox txtUrl;
  }

}
