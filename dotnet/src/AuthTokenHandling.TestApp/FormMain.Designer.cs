
namespace AuthTokenHandling.TestApp {
  partial class FormMain {
    /// <summary>
    ///  Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    ///  Clean up any resources being used.
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
    ///  Required method for Designer support - do not modify
    ///  the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent() {
      System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FormMain));
      tabControl1 = new System.Windows.Forms.TabControl();
      tabPage1 = new System.Windows.Forms.TabPage();
      cckUseHttpGetToRetrieve = new System.Windows.Forms.CheckBox();
      label8 = new System.Windows.Forms.Label();
      label7 = new System.Windows.Forms.Label();
      txtRedirectUrl = new System.Windows.Forms.TextBox();
      txtRetrievalCode = new System.Windows.Forms.TextBox();
      txtLoginHint = new System.Windows.Forms.TextBox();
      txtClientId = new System.Windows.Forms.TextBox();
      txtScopeToRequest = new System.Windows.Forms.TextBox();
      txtState = new System.Windows.Forms.TextBox();
      txtGrantType = new System.Windows.Forms.TextBox();
      txtRetrievalUrl = new System.Windows.Forms.TextBox();
      txtAuthorizeUrl = new System.Windows.Forms.TextBox();
      btnRetrieveToken = new System.Windows.Forms.Button();
      btnOpenLogonBrowser = new System.Windows.Forms.Button();
      label6 = new System.Windows.Forms.Label();
      label5 = new System.Windows.Forms.Label();
      label4 = new System.Windows.Forms.Label();
      label3 = new System.Windows.Forms.Label();
      label9 = new System.Windows.Forms.Label();
      label10 = new System.Windows.Forms.Label();
      label2 = new System.Windows.Forms.Label();
      label1 = new System.Windows.Forms.Label();
      comboBox1 = new System.Windows.Forms.ComboBox();
      tabPage2 = new System.Windows.Forms.TabPage();
      txtCurrentToken = new System.Windows.Forms.TextBox();
      button1 = new System.Windows.Forms.Button();
      button2 = new System.Windows.Forms.Button();
      tabControl1.SuspendLayout();
      tabPage1.SuspendLayout();
      this.SuspendLayout();
      // 
      // tabControl1
      // 
      tabControl1.Controls.Add(tabPage1);
      tabControl1.Controls.Add(tabPage2);
      tabControl1.Location = new System.Drawing.Point(30, 25);
      tabControl1.Name = "tabControl1";
      tabControl1.SelectedIndex = 0;
      tabControl1.Size = new System.Drawing.Size(591, 401);
      tabControl1.TabIndex = 0;
      // 
      // tabPage1
      // 
      tabPage1.Controls.Add(cckUseHttpGetToRetrieve);
      tabPage1.Controls.Add(label8);
      tabPage1.Controls.Add(label7);
      tabPage1.Controls.Add(txtRedirectUrl);
      tabPage1.Controls.Add(txtRetrievalCode);
      tabPage1.Controls.Add(txtLoginHint);
      tabPage1.Controls.Add(txtClientId);
      tabPage1.Controls.Add(txtScopeToRequest);
      tabPage1.Controls.Add(txtState);
      tabPage1.Controls.Add(txtGrantType);
      tabPage1.Controls.Add(txtRetrievalUrl);
      tabPage1.Controls.Add(txtAuthorizeUrl);
      tabPage1.Controls.Add(btnRetrieveToken);
      tabPage1.Controls.Add(btnOpenLogonBrowser);
      tabPage1.Controls.Add(label6);
      tabPage1.Controls.Add(label5);
      tabPage1.Controls.Add(label4);
      tabPage1.Controls.Add(label3);
      tabPage1.Controls.Add(label9);
      tabPage1.Controls.Add(label10);
      tabPage1.Controls.Add(label2);
      tabPage1.Controls.Add(label1);
      tabPage1.Controls.Add(comboBox1);
      tabPage1.Location = new System.Drawing.Point(4, 24);
      tabPage1.Name = "tabPage1";
      tabPage1.Padding = new System.Windows.Forms.Padding(3);
      tabPage1.Size = new System.Drawing.Size(583, 373);
      tabPage1.TabIndex = 0;
      tabPage1.Text = "Create Token";
      tabPage1.UseVisualStyleBackColor = true;
      // 
      // cckUseHttpGetToRetrieve
      // 
      cckUseHttpGetToRetrieve.AutoSize = true;
      cckUseHttpGetToRetrieve.Location = new System.Drawing.Point(263, 335);
      cckUseHttpGetToRetrieve.Name = "cckUseHttpGetToRetrieve";
      cckUseHttpGetToRetrieve.Size = new System.Drawing.Size(229, 19);
      cckUseHttpGetToRetrieve.TabIndex = 6;
      cckUseHttpGetToRetrieve.Text = "use HTTP-GET to retrieve (special case)";
      cckUseHttpGetToRetrieve.UseVisualStyleBackColor = true;
      // 
      // label8
      // 
      label8.AutoSize = true;
      label8.Location = new System.Drawing.Point(43, 112);
      label8.Name = "label8";
      label8.Size = new System.Drawing.Size(66, 15);
      label8.TabIndex = 5;
      label8.Text = "redirect_uri";
      // 
      // label7
      // 
      label7.AutoSize = true;
      label7.Location = new System.Drawing.Point(43, 242);
      label7.Name = "label7";
      label7.Size = new System.Drawing.Size(60, 15);
      label7.TabIndex = 5;
      label7.Text = "login_hint";
      // 
      // txtRedirectUrl
      // 
      txtRedirectUrl.BackColor = System.Drawing.SystemColors.Window;
      txtRedirectUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtRedirectUrl.Location = new System.Drawing.Point(263, 111);
      txtRedirectUrl.Name = "txtRedirectUrl";
      txtRedirectUrl.Size = new System.Drawing.Size(279, 20);
      txtRedirectUrl.TabIndex = 4;
      txtRedirectUrl.Text = "https://localhost";
      // 
      // txtRetrievalCode
      // 
      txtRetrievalCode.BackColor = System.Drawing.SystemColors.Window;
      txtRetrievalCode.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtRetrievalCode.Location = new System.Drawing.Point(263, 309);
      txtRetrievalCode.Name = "txtRetrievalCode";
      txtRetrievalCode.Size = new System.Drawing.Size(279, 20);
      txtRetrievalCode.TabIndex = 4;
      // 
      // txtLoginHint
      // 
      txtLoginHint.BackColor = System.Drawing.SystemColors.Window;
      txtLoginHint.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtLoginHint.Location = new System.Drawing.Point(263, 241);
      txtLoginHint.Name = "txtLoginHint";
      txtLoginHint.Size = new System.Drawing.Size(279, 20);
      txtLoginHint.TabIndex = 4;
      txtLoginHint.Text = "API-CLIENT";
      // 
      // txtClientId
      // 
      txtClientId.BackColor = System.Drawing.SystemColors.Window;
      txtClientId.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtClientId.Location = new System.Drawing.Point(263, 215);
      txtClientId.Name = "txtClientId";
      txtClientId.Size = new System.Drawing.Size(279, 20);
      txtClientId.TabIndex = 4;
      txtClientId.Text = "master";
      // 
      // txtScopeToRequest
      // 
      txtScopeToRequest.BackColor = System.Drawing.SystemColors.Window;
      txtScopeToRequest.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtScopeToRequest.Location = new System.Drawing.Point(263, 189);
      txtScopeToRequest.Name = "txtScopeToRequest";
      txtScopeToRequest.Size = new System.Drawing.Size(279, 20);
      txtScopeToRequest.TabIndex = 4;
      txtScopeToRequest.Text = "API:AccessTokenValidator%20API:EnvironmentAdministration%20API:EnvironmentSetup%20API:UserAdminstration";
      // 
      // txtState
      // 
      txtState.BackColor = System.Drawing.SystemColors.Window;
      txtState.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtState.Location = new System.Drawing.Point(263, 163);
      txtState.Name = "txtState";
      txtState.Size = new System.Drawing.Size(279, 20);
      txtState.TabIndex = 4;
      txtState.Text = "dummy";
      // 
      // txtGrantType
      // 
      txtGrantType.BackColor = System.Drawing.SystemColors.Window;
      txtGrantType.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtGrantType.Location = new System.Drawing.Point(263, 137);
      txtGrantType.Name = "txtGrantType";
      txtGrantType.Size = new System.Drawing.Size(279, 20);
      txtGrantType.TabIndex = 4;
      txtGrantType.Text = "code";
      // 
      // txtRetrievalUrl
      // 
      txtRetrievalUrl.BackColor = System.Drawing.SystemColors.Window;
      txtRetrievalUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtRetrievalUrl.Location = new System.Drawing.Point(159, 283);
      txtRetrievalUrl.Name = "txtRetrievalUrl";
      txtRetrievalUrl.Size = new System.Drawing.Size(226, 20);
      txtRetrievalUrl.TabIndex = 3;
      txtRetrievalUrl.Text = "https://localhost:44351/token";
      // 
      // txtAuthorizeUrl
      // 
      txtAuthorizeUrl.BackColor = System.Drawing.SystemColors.Window;
      txtAuthorizeUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtAuthorizeUrl.Location = new System.Drawing.Point(159, 85);
      txtAuthorizeUrl.Name = "txtAuthorizeUrl";
      txtAuthorizeUrl.Size = new System.Drawing.Size(230, 20);
      txtAuthorizeUrl.TabIndex = 3;
      txtAuthorizeUrl.Text = "https://localhost:44351/oauth";
      // 
      // btnRetrieveToken
      // 
      btnRetrieveToken.Location = new System.Drawing.Point(391, 283);
      btnRetrieveToken.Name = "btnRetrieveToken";
      btnRetrieveToken.Size = new System.Drawing.Size(151, 20);
      btnRetrieveToken.TabIndex = 2;
      btnRetrieveToken.Text = "retrieve token";
      btnRetrieveToken.UseVisualStyleBackColor = true;
      btnRetrieveToken.Click += this.button3_Click;
      // 
      // btnOpenLogonBrowser
      // 
      btnOpenLogonBrowser.Location = new System.Drawing.Point(395, 85);
      btnOpenLogonBrowser.Name = "btnOpenLogonBrowser";
      btnOpenLogonBrowser.Size = new System.Drawing.Size(147, 20);
      btnOpenLogonBrowser.TabIndex = 2;
      btnOpenLogonBrowser.Text = "open Browser to Logon";
      btnOpenLogonBrowser.UseVisualStyleBackColor = true;
      btnOpenLogonBrowser.Click += this.button3_Click;
      // 
      // label6
      // 
      label6.AutoSize = true;
      label6.Location = new System.Drawing.Point(43, 216);
      label6.Name = "label6";
      label6.Size = new System.Drawing.Size(51, 15);
      label6.TabIndex = 1;
      label6.Text = "client_id";
      // 
      // label5
      // 
      label5.AutoSize = true;
      label5.Location = new System.Drawing.Point(43, 190);
      label5.Name = "label5";
      label5.Size = new System.Drawing.Size(38, 15);
      label5.TabIndex = 1;
      label5.Text = "scope";
      // 
      // label4
      // 
      label4.AutoSize = true;
      label4.Location = new System.Drawing.Point(43, 164);
      label4.Name = "label4";
      label4.Size = new System.Drawing.Size(32, 15);
      label4.TabIndex = 1;
      label4.Text = "state";
      // 
      // label3
      // 
      label3.AutoSize = true;
      label3.Location = new System.Drawing.Point(43, 138);
      label3.Name = "label3";
      label3.Size = new System.Drawing.Size(63, 15);
      label3.TabIndex = 1;
      label3.Text = "grant_type";
      // 
      // label9
      // 
      label9.AutoSize = true;
      label9.Location = new System.Drawing.Point(43, 310);
      label9.Name = "label9";
      label9.Size = new System.Drawing.Size(214, 15);
      label9.TabIndex = 1;
      label9.Text = "Retrieval Code (from URL after redirect)";
      // 
      // label10
      // 
      label10.AutoSize = true;
      label10.Location = new System.Drawing.Point(23, 284);
      label10.Name = "label10";
      label10.Size = new System.Drawing.Size(124, 15);
      label10.TabIndex = 1;
      label10.Text = "Retrieval-URL (OAuth)";
      // 
      // label2
      // 
      label2.AutoSize = true;
      label2.Location = new System.Drawing.Point(23, 86);
      label2.Name = "label2";
      label2.Size = new System.Drawing.Size(130, 15);
      label2.TabIndex = 1;
      label2.Text = "Authorize-URL (OAuth)";
      // 
      // label1
      // 
      label1.AutoSize = true;
      label1.Location = new System.Drawing.Point(6, 14);
      label1.Name = "label1";
      label1.Size = new System.Drawing.Size(41, 15);
      label1.TabIndex = 1;
      label1.Text = "MODE";
      // 
      // comboBox1
      // 
      comboBox1.FormattingEnabled = true;
      comboBox1.Location = new System.Drawing.Point(79, 11);
      comboBox1.Name = "comboBox1";
      comboBox1.Size = new System.Drawing.Size(238, 23);
      comboBox1.TabIndex = 0;
      // 
      // tabPage2
      // 
      tabPage2.Location = new System.Drawing.Point(4, 24);
      tabPage2.Name = "tabPage2";
      tabPage2.Padding = new System.Windows.Forms.Padding(3);
      tabPage2.Size = new System.Drawing.Size(583, 373);
      tabPage2.TabIndex = 1;
      tabPage2.Text = "Validate Token";
      tabPage2.UseVisualStyleBackColor = true;
      // 
      // txtCurrentToken
      // 
      txtCurrentToken.Location = new System.Drawing.Point(30, 432);
      txtCurrentToken.Multiline = true;
      txtCurrentToken.Name = "txtCurrentToken";
      txtCurrentToken.Size = new System.Drawing.Size(591, 98);
      txtCurrentToken.TabIndex = 1;
      // 
      // button1
      // 
      button1.Location = new System.Drawing.Point(424, 7);
      button1.Name = "button1";
      button1.Size = new System.Drawing.Size(92, 36);
      button1.TabIndex = 2;
      button1.Text = "Export Config";
      button1.UseVisualStyleBackColor = true;
      // 
      // button2
      // 
      button2.Location = new System.Drawing.Point(525, 7);
      button2.Name = "button2";
      button2.Size = new System.Drawing.Size(92, 36);
      button2.TabIndex = 3;
      button2.Text = "Import Config";
      button2.UseVisualStyleBackColor = true;
      // 
      // FormMain
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(652, 563);
      this.Controls.Add(button2);
      this.Controls.Add(button1);
      this.Controls.Add(txtCurrentToken);
      this.Controls.Add(tabControl1);
      this.Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
      this.Name = "FormMain";
      this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
      this.Text = "AuthTest.exe";
      tabControl1.ResumeLayout(false);
      tabPage1.ResumeLayout(false);
      tabPage1.PerformLayout();
      this.ResumeLayout(false);
      this.PerformLayout();
    }

    #endregion

    private System.Windows.Forms.TabControl tabControl1;
    private System.Windows.Forms.TabPage tabPage1;
    private System.Windows.Forms.Button btnOpenLogonBrowser;
    private System.Windows.Forms.Label label1;
    private System.Windows.Forms.ComboBox comboBox1;
    private System.Windows.Forms.TabPage tabPage2;
    private System.Windows.Forms.TextBox txtCurrentToken;
    private System.Windows.Forms.Button button1;
    private System.Windows.Forms.Button button2;
    private System.Windows.Forms.TextBox txtAuthorizeUrl;
    private System.Windows.Forms.Label label8;
    private System.Windows.Forms.Label label7;
    private System.Windows.Forms.TextBox txtRedirectUrl;
    private System.Windows.Forms.TextBox txtLoginHint;
    private System.Windows.Forms.TextBox txtClientId;
    private System.Windows.Forms.TextBox txtScopeToRequest;
    private System.Windows.Forms.TextBox txtState;
    private System.Windows.Forms.TextBox txtGrantType;
    private System.Windows.Forms.Label label6;
    private System.Windows.Forms.Label label5;
    private System.Windows.Forms.Label label4;
    private System.Windows.Forms.Label label3;
    private System.Windows.Forms.Label label2;
    private System.Windows.Forms.CheckBox cckUseHttpGetToRetrieve;
    private System.Windows.Forms.TextBox txtRetrievalCode;
    private System.Windows.Forms.TextBox txtRetrievalUrl;
    private System.Windows.Forms.Button btnRetrieveToken;
    private System.Windows.Forms.Label label9;
    private System.Windows.Forms.Label label10;
  }
}

