﻿
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
      btlSilent = new System.Windows.Forms.Button();
      cckUseHttpGetToRetrieve = new System.Windows.Forms.CheckBox();
      label8 = new System.Windows.Forms.Label();
      label12 = new System.Windows.Forms.Label();
      label7 = new System.Windows.Forms.Label();
      txtRedirectUrl = new System.Windows.Forms.TextBox();
      txtClientSecret = new System.Windows.Forms.TextBox();
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
      btnIntrospect = new System.Windows.Forms.Button();
      txtIntrospectionUrl = new System.Windows.Forms.TextBox();
      tabPage3 = new System.Windows.Forms.TabPage();
      tabPage4 = new System.Windows.Forms.TabPage();
      txtCurrentToken = new System.Windows.Forms.TextBox();
      button1 = new System.Windows.Forms.Button();
      button2 = new System.Windows.Forms.Button();
      label11 = new System.Windows.Forms.Label();
      txtTokenContent = new System.Windows.Forms.TextBox();
      label13 = new System.Windows.Forms.Label();
      txtTokenState = new System.Windows.Forms.TextBox();
      txtCurrentRefreshToken = new System.Windows.Forms.TextBox();
      txtCurrentIdToken = new System.Windows.Forms.TextBox();
      label14 = new System.Windows.Forms.Label();
      label15 = new System.Windows.Forms.Label();
      tabControl1.SuspendLayout();
      tabPage1.SuspendLayout();
      tabPage2.SuspendLayout();
      this.SuspendLayout();
      // 
      // tabControl1
      // 
      tabControl1.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      tabControl1.Controls.Add(tabPage1);
      tabControl1.Controls.Add(tabPage2);
      tabControl1.Controls.Add(tabPage3);
      tabControl1.Controls.Add(tabPage4);
      tabControl1.Location = new System.Drawing.Point(14, 67);
      tabControl1.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabControl1.Name = "tabControl1";
      tabControl1.SelectedIndex = 0;
      tabControl1.Size = new System.Drawing.Size(833, 700);
      tabControl1.TabIndex = 0;
      // 
      // tabPage1
      // 
      tabPage1.Controls.Add(btlSilent);
      tabPage1.Controls.Add(cckUseHttpGetToRetrieve);
      tabPage1.Controls.Add(label8);
      tabPage1.Controls.Add(label12);
      tabPage1.Controls.Add(label7);
      tabPage1.Controls.Add(txtRedirectUrl);
      tabPage1.Controls.Add(txtClientSecret);
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
      tabPage1.Location = new System.Drawing.Point(4, 29);
      tabPage1.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabPage1.Name = "tabPage1";
      tabPage1.Padding = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabPage1.Size = new System.Drawing.Size(825, 667);
      tabPage1.TabIndex = 0;
      tabPage1.Text = "Request Token (from OAuth Svc)";
      tabPage1.UseVisualStyleBackColor = true;
      // 
      // btlSilent
      // 
      btlSilent.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      btlSilent.Location = new System.Drawing.Point(784, 115);
      btlSilent.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      btlSilent.Name = "btlSilent";
      btlSilent.Size = new System.Drawing.Size(19, 25);
      btlSilent.TabIndex = 7;
      btlSilent.Text = "S";
      btlSilent.UseVisualStyleBackColor = true;
      btlSilent.Click += this.btlSilent_Click;
      // 
      // cckUseHttpGetToRetrieve
      // 
      cckUseHttpGetToRetrieve.AutoSize = true;
      cckUseHttpGetToRetrieve.Location = new System.Drawing.Point(301, 551);
      cckUseHttpGetToRetrieve.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      cckUseHttpGetToRetrieve.Name = "cckUseHttpGetToRetrieve";
      cckUseHttpGetToRetrieve.Size = new System.Drawing.Size(289, 24);
      cckUseHttpGetToRetrieve.TabIndex = 6;
      cckUseHttpGetToRetrieve.Text = "use HTTP-GET to retrieve (special case)";
      cckUseHttpGetToRetrieve.UseVisualStyleBackColor = true;
      // 
      // label8
      // 
      label8.AutoSize = true;
      label8.Location = new System.Drawing.Point(49, 149);
      label8.Name = "label8";
      label8.Size = new System.Drawing.Size(83, 20);
      label8.TabIndex = 5;
      label8.Text = "redirect_uri";
      // 
      // label12
      // 
      label12.AutoSize = true;
      label12.Location = new System.Drawing.Point(49, 407);
      label12.Name = "label12";
      label12.Size = new System.Drawing.Size(90, 20);
      label12.TabIndex = 5;
      label12.Text = "client_secret";
      // 
      // label7
      // 
      label7.AutoSize = true;
      label7.Location = new System.Drawing.Point(49, 441);
      label7.Name = "label7";
      label7.Size = new System.Drawing.Size(74, 20);
      label7.TabIndex = 5;
      label7.Text = "login_hint";
      // 
      // txtRedirectUrl
      // 
      txtRedirectUrl.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtRedirectUrl.BackColor = System.Drawing.SystemColors.Window;
      txtRedirectUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtRedirectUrl.Location = new System.Drawing.Point(301, 148);
      txtRedirectUrl.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtRedirectUrl.Name = "txtRedirectUrl";
      txtRedirectUrl.Size = new System.Drawing.Size(476, 24);
      txtRedirectUrl.TabIndex = 4;
      txtRedirectUrl.Text = "https://localhost";
      // 
      // txtClientSecret
      // 
      txtClientSecret.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtClientSecret.BackColor = System.Drawing.SystemColors.Window;
      txtClientSecret.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtClientSecret.Location = new System.Drawing.Point(301, 405);
      txtClientSecret.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtClientSecret.Name = "txtClientSecret";
      txtClientSecret.Size = new System.Drawing.Size(476, 24);
      txtClientSecret.TabIndex = 4;
      txtClientSecret.Text = "cool";
      txtClientSecret.UseSystemPasswordChar = true;
      // 
      // txtRetrievalCode
      // 
      txtRetrievalCode.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtRetrievalCode.BackColor = System.Drawing.SystemColors.Window;
      txtRetrievalCode.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtRetrievalCode.Location = new System.Drawing.Point(301, 516);
      txtRetrievalCode.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtRetrievalCode.Name = "txtRetrievalCode";
      txtRetrievalCode.Size = new System.Drawing.Size(476, 24);
      txtRetrievalCode.TabIndex = 4;
      // 
      // txtLoginHint
      // 
      txtLoginHint.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtLoginHint.BackColor = System.Drawing.SystemColors.Window;
      txtLoginHint.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtLoginHint.Location = new System.Drawing.Point(301, 440);
      txtLoginHint.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtLoginHint.Name = "txtLoginHint";
      txtLoginHint.Size = new System.Drawing.Size(476, 24);
      txtLoginHint.TabIndex = 4;
      txtLoginHint.Text = "API-CLIENT";
      // 
      // txtClientId
      // 
      txtClientId.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtClientId.BackColor = System.Drawing.SystemColors.Window;
      txtClientId.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtClientId.Location = new System.Drawing.Point(301, 371);
      txtClientId.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtClientId.Name = "txtClientId";
      txtClientId.Size = new System.Drawing.Size(476, 24);
      txtClientId.TabIndex = 4;
      txtClientId.Text = "master";
      // 
      // txtScopeToRequest
      // 
      txtScopeToRequest.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtScopeToRequest.BackColor = System.Drawing.SystemColors.Window;
      txtScopeToRequest.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtScopeToRequest.Location = new System.Drawing.Point(301, 252);
      txtScopeToRequest.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtScopeToRequest.Multiline = true;
      txtScopeToRequest.Name = "txtScopeToRequest";
      txtScopeToRequest.Size = new System.Drawing.Size(476, 109);
      txtScopeToRequest.TabIndex = 4;
      txtScopeToRequest.Text = "API:AccessTokenValidator%20API:EnvironmentAdministration%20API:EnvironmentSetup%20API:UserAdminstration";
      // 
      // txtState
      // 
      txtState.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtState.BackColor = System.Drawing.SystemColors.Window;
      txtState.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtState.Location = new System.Drawing.Point(301, 217);
      txtState.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtState.Name = "txtState";
      txtState.Size = new System.Drawing.Size(476, 24);
      txtState.TabIndex = 4;
      txtState.Text = "dummy";
      // 
      // txtGrantType
      // 
      txtGrantType.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtGrantType.BackColor = System.Drawing.SystemColors.Window;
      txtGrantType.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtGrantType.Location = new System.Drawing.Point(301, 183);
      txtGrantType.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtGrantType.Name = "txtGrantType";
      txtGrantType.Size = new System.Drawing.Size(476, 24);
      txtGrantType.TabIndex = 4;
      txtGrantType.Text = "code";
      // 
      // txtRetrievalUrl
      // 
      txtRetrievalUrl.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtRetrievalUrl.BackColor = System.Drawing.SystemColors.Window;
      txtRetrievalUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtRetrievalUrl.Location = new System.Drawing.Point(182, 481);
      txtRetrievalUrl.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtRetrievalUrl.Name = "txtRetrievalUrl";
      txtRetrievalUrl.Size = new System.Drawing.Size(415, 24);
      txtRetrievalUrl.TabIndex = 3;
      txtRetrievalUrl.Text = "https://localhost:44351/oauth2/token";
      // 
      // txtAuthorizeUrl
      // 
      txtAuthorizeUrl.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtAuthorizeUrl.BackColor = System.Drawing.SystemColors.Window;
      txtAuthorizeUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtAuthorizeUrl.Location = new System.Drawing.Point(182, 113);
      txtAuthorizeUrl.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtAuthorizeUrl.Name = "txtAuthorizeUrl";
      txtAuthorizeUrl.Size = new System.Drawing.Size(420, 24);
      txtAuthorizeUrl.TabIndex = 3;
      txtAuthorizeUrl.Text = "https://localhost:44351/oauth2/authorize";
      // 
      // btnRetrieveToken
      // 
      btnRetrieveToken.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      btnRetrieveToken.Location = new System.Drawing.Point(605, 481);
      btnRetrieveToken.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      btnRetrieveToken.Name = "btnRetrieveToken";
      btnRetrieveToken.Size = new System.Drawing.Size(173, 27);
      btnRetrieveToken.TabIndex = 2;
      btnRetrieveToken.Text = "retrieve token";
      btnRetrieveToken.UseVisualStyleBackColor = true;
      btnRetrieveToken.Click += this.btnRetrieveToken_Click;
      // 
      // btnOpenLogonBrowser
      // 
      btnOpenLogonBrowser.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      btnOpenLogonBrowser.Location = new System.Drawing.Point(609, 113);
      btnOpenLogonBrowser.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      btnOpenLogonBrowser.Name = "btnOpenLogonBrowser";
      btnOpenLogonBrowser.Size = new System.Drawing.Size(168, 27);
      btnOpenLogonBrowser.TabIndex = 2;
      btnOpenLogonBrowser.Text = "open Browser to Logon";
      btnOpenLogonBrowser.UseVisualStyleBackColor = true;
      btnOpenLogonBrowser.Click += this.btnOpenLogonBrowser_Click;
      // 
      // label6
      // 
      label6.AutoSize = true;
      label6.Location = new System.Drawing.Point(49, 372);
      label6.Name = "label6";
      label6.Size = new System.Drawing.Size(64, 20);
      label6.TabIndex = 1;
      label6.Text = "client_id";
      // 
      // label5
      // 
      label5.AutoSize = true;
      label5.Location = new System.Drawing.Point(49, 253);
      label5.Name = "label5";
      label5.Size = new System.Drawing.Size(48, 20);
      label5.TabIndex = 1;
      label5.Text = "scope";
      // 
      // label4
      // 
      label4.AutoSize = true;
      label4.Location = new System.Drawing.Point(49, 219);
      label4.Name = "label4";
      label4.Size = new System.Drawing.Size(41, 20);
      label4.TabIndex = 1;
      label4.Text = "state";
      // 
      // label3
      // 
      label3.AutoSize = true;
      label3.Location = new System.Drawing.Point(49, 184);
      label3.Name = "label3";
      label3.Size = new System.Drawing.Size(79, 20);
      label3.TabIndex = 1;
      label3.Text = "grant_type";
      // 
      // label9
      // 
      label9.AutoSize = true;
      label9.Location = new System.Drawing.Point(49, 517);
      label9.Name = "label9";
      label9.Size = new System.Drawing.Size(272, 20);
      label9.TabIndex = 1;
      label9.Text = "Retrieval Code (from URL after redirect)";
      // 
      // label10
      // 
      label10.AutoSize = true;
      label10.Location = new System.Drawing.Point(26, 483);
      label10.Name = "label10";
      label10.Size = new System.Drawing.Size(155, 20);
      label10.TabIndex = 1;
      label10.Text = "Retrieval-URL (OAuth)";
      // 
      // label2
      // 
      label2.AutoSize = true;
      label2.Location = new System.Drawing.Point(26, 115);
      label2.Name = "label2";
      label2.Size = new System.Drawing.Size(161, 20);
      label2.TabIndex = 1;
      label2.Text = "Authorize-URL (OAuth)";
      // 
      // label1
      // 
      label1.AutoSize = true;
      label1.Location = new System.Drawing.Point(7, 19);
      label1.Name = "label1";
      label1.Size = new System.Drawing.Size(52, 20);
      label1.TabIndex = 1;
      label1.Text = "MODE";
      // 
      // comboBox1
      // 
      comboBox1.Enabled = false;
      comboBox1.FormattingEnabled = true;
      comboBox1.Location = new System.Drawing.Point(90, 15);
      comboBox1.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      comboBox1.Name = "comboBox1";
      comboBox1.Size = new System.Drawing.Size(271, 28);
      comboBox1.TabIndex = 0;
      // 
      // tabPage2
      // 
      tabPage2.Controls.Add(btnIntrospect);
      tabPage2.Controls.Add(txtIntrospectionUrl);
      tabPage2.Location = new System.Drawing.Point(4, 29);
      tabPage2.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabPage2.Name = "tabPage2";
      tabPage2.Padding = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabPage2.Size = new System.Drawing.Size(825, 667);
      tabPage2.TabIndex = 1;
      tabPage2.Text = "Introspect Token (via OAuth Svc)";
      tabPage2.UseVisualStyleBackColor = true;
      // 
      // btnIntrospect
      // 
      btnIntrospect.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      btnIntrospect.Location = new System.Drawing.Point(656, 37);
      btnIntrospect.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      btnIntrospect.Name = "btnIntrospect";
      btnIntrospect.Size = new System.Drawing.Size(133, 27);
      btnIntrospect.TabIndex = 5;
      btnIntrospect.Text = "Introspect";
      btnIntrospect.UseVisualStyleBackColor = true;
      btnIntrospect.Click += this.btnIntrospect_Click;
      // 
      // txtIntrospectionUrl
      // 
      txtIntrospectionUrl.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtIntrospectionUrl.BackColor = System.Drawing.SystemColors.Window;
      txtIntrospectionUrl.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtIntrospectionUrl.Location = new System.Drawing.Point(29, 37);
      txtIntrospectionUrl.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtIntrospectionUrl.Name = "txtIntrospectionUrl";
      txtIntrospectionUrl.Size = new System.Drawing.Size(620, 24);
      txtIntrospectionUrl.TabIndex = 4;
      txtIntrospectionUrl.Text = "https://localhost:44351/oauth2/introspect";
      txtIntrospectionUrl.TextChanged += this.txtIntrospectionUrl_TextChanged;
      // 
      // tabPage3
      // 
      tabPage3.Location = new System.Drawing.Point(4, 29);
      tabPage3.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabPage3.Name = "tabPage3";
      tabPage3.Size = new System.Drawing.Size(825, 667);
      tabPage3.TabIndex = 2;
      tabPage3.Text = "Generate Token locally (JWT)";
      tabPage3.UseVisualStyleBackColor = true;
      // 
      // tabPage4
      // 
      tabPage4.Location = new System.Drawing.Point(4, 29);
      tabPage4.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      tabPage4.Name = "tabPage4";
      tabPage4.Size = new System.Drawing.Size(825, 667);
      tabPage4.TabIndex = 3;
      tabPage4.Text = "Introspect Token locally (JWT only)";
      tabPage4.UseVisualStyleBackColor = true;
      // 
      // txtCurrentToken
      // 
      txtCurrentToken.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtCurrentToken.Location = new System.Drawing.Point(14, 795);
      txtCurrentToken.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtCurrentToken.Name = "txtCurrentToken";
      txtCurrentToken.Size = new System.Drawing.Size(828, 27);
      txtCurrentToken.TabIndex = 1;
      // 
      // button1
      // 
      button1.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      button1.Enabled = false;
      button1.Location = new System.Drawing.Point(854, 9);
      button1.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      button1.Name = "button1";
      button1.Size = new System.Drawing.Size(125, 48);
      button1.TabIndex = 2;
      button1.Text = "Export Config";
      button1.UseVisualStyleBackColor = true;
      button1.Click += this.button1_Click;
      // 
      // button2
      // 
      button2.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      button2.Enabled = false;
      button2.Location = new System.Drawing.Point(985, 9);
      button2.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      button2.Name = "button2";
      button2.Size = new System.Drawing.Size(125, 48);
      button2.TabIndex = 3;
      button2.Text = "Import Config";
      button2.UseVisualStyleBackColor = true;
      // 
      // label11
      // 
      label11.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      label11.AutoSize = true;
      label11.Location = new System.Drawing.Point(14, 771);
      label11.Name = "label11";
      label11.Size = new System.Drawing.Size(98, 20);
      label11.TabIndex = 4;
      label11.Text = "Access-Token";
      // 
      // txtTokenContent
      // 
      txtTokenContent.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
      txtTokenContent.Font = new System.Drawing.Font("Consolas", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
      txtTokenContent.Location = new System.Drawing.Point(854, 96);
      txtTokenContent.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtTokenContent.Multiline = true;
      txtTokenContent.Name = "txtTokenContent";
      txtTokenContent.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
      txtTokenContent.Size = new System.Drawing.Size(255, 813);
      txtTokenContent.TabIndex = 1;
      txtTokenContent.TextChanged += this.txtTokenContent_TextChanged;
      // 
      // label13
      // 
      label13.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
      label13.AutoSize = true;
      label13.Location = new System.Drawing.Point(854, 69);
      label13.Name = "label13";
      label13.Size = new System.Drawing.Size(53, 20);
      label13.TabIndex = 4;
      label13.Text = "Claims";
      // 
      // txtTokenState
      // 
      txtTokenState.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
      txtTokenState.BackColor = System.Drawing.SystemColors.Window;
      txtTokenState.Font = new System.Drawing.Font("Consolas", 11.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
      txtTokenState.Location = new System.Drawing.Point(854, 909);
      txtTokenState.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtTokenState.Name = "txtTokenState";
      txtTokenState.ReadOnly = true;
      txtTokenState.Size = new System.Drawing.Size(255, 29);
      txtTokenState.TabIndex = 4;
      txtTokenState.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
      // 
      // txtCurrentRefreshToken
      // 
      txtCurrentRefreshToken.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtCurrentRefreshToken.Location = new System.Drawing.Point(14, 853);
      txtCurrentRefreshToken.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtCurrentRefreshToken.Name = "txtCurrentRefreshToken";
      txtCurrentRefreshToken.Size = new System.Drawing.Size(828, 27);
      txtCurrentRefreshToken.TabIndex = 1;
      // 
      // txtCurrentIdToken
      // 
      txtCurrentIdToken.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      txtCurrentIdToken.Location = new System.Drawing.Point(14, 912);
      txtCurrentIdToken.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      txtCurrentIdToken.Name = "txtCurrentIdToken";
      txtCurrentIdToken.Size = new System.Drawing.Size(828, 27);
      txtCurrentIdToken.TabIndex = 1;
      // 
      // label14
      // 
      label14.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      label14.AutoSize = true;
      label14.Location = new System.Drawing.Point(14, 829);
      label14.Name = "label14";
      label14.Size = new System.Drawing.Size(103, 20);
      label14.TabIndex = 4;
      label14.Text = "Refresh-Token";
      // 
      // label15
      // 
      label15.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
      label15.AutoSize = true;
      label15.Location = new System.Drawing.Point(14, 888);
      label15.Name = "label15";
      label15.Size = new System.Drawing.Size(69, 20);
      label15.TabIndex = 4;
      label15.Text = "ID-Token";
      // 
      // FormMain
      // 
      this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
      this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
      this.ClientSize = new System.Drawing.Size(1123, 957);
      this.Controls.Add(label13);
      this.Controls.Add(txtTokenState);
      this.Controls.Add(label15);
      this.Controls.Add(label14);
      this.Controls.Add(label11);
      this.Controls.Add(button2);
      this.Controls.Add(button1);
      this.Controls.Add(txtTokenContent);
      this.Controls.Add(txtCurrentIdToken);
      this.Controls.Add(txtCurrentRefreshToken);
      this.Controls.Add(txtCurrentToken);
      this.Controls.Add(tabControl1);
      this.Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
      this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
      this.Name = "FormMain";
      this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
      this.Text = "AuthTest.exe (by Smart Standards)";
      this.Load += this.FormMain_Load;
      tabControl1.ResumeLayout(false);
      tabPage1.ResumeLayout(false);
      tabPage1.PerformLayout();
      tabPage2.ResumeLayout(false);
      tabPage2.PerformLayout();
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
    private System.Windows.Forms.Label label11;
    private System.Windows.Forms.Label label12;
    private System.Windows.Forms.TextBox txtClientSecret;
    private System.Windows.Forms.TabPage tabPage3;
    private System.Windows.Forms.TabPage tabPage4;
    private System.Windows.Forms.TextBox txtIntrospectionUrl;
    private System.Windows.Forms.Button btnIntrospect;
    private System.Windows.Forms.TextBox txtTokenContent;
    private System.Windows.Forms.Label label13;
    private System.Windows.Forms.TextBox txtTokenState;
    private System.Windows.Forms.Button btlSilent;
    private System.Windows.Forms.TextBox txtCurrentRefreshToken;
    private System.Windows.Forms.TextBox txtCurrentIdToken;
    private System.Windows.Forms.Label label14;
    private System.Windows.Forms.Label label15;
  }
}

