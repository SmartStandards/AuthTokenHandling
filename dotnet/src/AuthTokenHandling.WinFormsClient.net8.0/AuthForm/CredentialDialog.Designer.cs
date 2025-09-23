using System.Windows.Forms;

namespace Security.AccessTokenHandling {

  partial class CredentialDialog {
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
      System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CredentialDialog));
      btnOK = new Button();
      btnCancel = new Button();
      this.SuspendLayout();
      // 
      // btnOK
      // 
      btnOK.Location = new System.Drawing.Point(240, 154);
      btnOK.Name = "btnOK";
      btnOK.Size = new System.Drawing.Size(69, 34);
      btnOK.TabIndex = 0;
      btnOK.Text = "OK";
      btnOK.UseVisualStyleBackColor = true;
      btnOK.Click += this.btnOK_Click;
      // 
      // btnCancel
      // 
      btnCancel.Location = new System.Drawing.Point(165, 154);
      btnCancel.Name = "btnCancel";
      btnCancel.Size = new System.Drawing.Size(69, 34);
      btnCancel.TabIndex = 0;
      btnCancel.Text = "Cancel";
      btnCancel.UseVisualStyleBackColor = true;
      btnCancel.Click += this.btnCancel_Click;
      // 
      // CredentialDialog
      // 
      this.ClientSize = new System.Drawing.Size(321, 200);
      this.Controls.Add(btnCancel);
      this.Controls.Add(btnOK);
      this.Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
      this.Name = "CredentialDialog";
      this.Load += this.CredentialDialog_Load;
      this.ResumeLayout(false);
    }

    #endregion

    private Button btnOK;
    private Button btnCancel;
  }

}
