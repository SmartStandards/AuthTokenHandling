using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

namespace Security.AccessTokenHandling {

  internal partial class CredentialDialog : Form {

    public CredentialDialog() {
      this.InitializeComponent();
    }

    private List<TextBox> _InputBoxes = new List<TextBox>();
    private Dictionary<string, object> _ClaimsToEdit =null;

    public Dictionary<string, object> ClaimsToEdit {
      get {
        return _ClaimsToEdit;
      }
      set {
        _ClaimsToEdit = value;
        if(_ClaimsToEdit == null) {
          return;
        }
        foreach (TextBox box in _InputBoxes) {
          if (_ClaimsToEdit.ContainsKey(box.Name) && !String.IsNullOrWhiteSpace(_ClaimsToEdit[box.Name]?.ToString())) {
            box.Text = _ClaimsToEdit[box.Name]?.ToString();
          }
        }
      }
    }

    internal TextBox GetOrCreateBox(string claimName, string displayLabel, bool isPassword, bool isOptional, object defaultValue) {

      const int spacing = 20;
      const int labelWidth = 80;

      TextBox box = _InputBoxes.Where((b)=>b.Name == claimName).FirstOrDefault();

      if(box == null) {

        int top = 20;
        if (_InputBoxes.Any()) {
          top = _InputBoxes.Last().Top + _InputBoxes.Last().Height + 10;
        }

        box = new TextBox();

        //equality required!!!
        box.Name = claimName;

        Label lbl = new Label();
        lbl.Name = "lbl_" + claimName;

        box.Top = top;
        box.Left = (spacing * 2) + labelWidth;
        box.Width = this.ClientSize.Width - (spacing * 3) - labelWidth;
  
        lbl.Top = top; //align with textbox
        lbl.Left = spacing;
        lbl.Width = labelWidth;

        if (isPassword) {
          box.UseSystemPasswordChar = true;
        }
        if (defaultValue != null) {
          box.Text = defaultValue.ToString();
        }

        lbl.Text = displayLabel + (isOptional ? "" : "*");

        box.Tag = claimName + (isOptional ? "" : "*");

        lbl.Visible = true;
        box.Visible = true;

        box.TextChanged += OnTextboxChanged;

        this.Container.Add(lbl);
        this.Container.Add(box);

        _InputBoxes.Add(box);
      }
 
      return box;
    }

    private void OnTextboxChanged(object sender, EventArgs e) {

      TextBox input = (sender as TextBox);
      string claimName = input.Tag as string;

      bool optional = true;

      if (claimName.EndsWith("*")) {
        claimName = claimName.Substring(0, claimName.Length - 1);
        optional = false;
      }

      if (this.ClaimsToEdit != null) {
        this.ClaimsToEdit[claimName] = input.Text;
      }

    }

    internal void RegisterPromt(string claimName, string displayLabel, bool isHiddenInput, bool isOptional, object defaultValue) {
      if (this.ClaimsToEdit != null) {
        this.ClaimsToEdit.TryGetValue(claimName, out defaultValue);
      }
      TextBox box = GetOrCreateBox(claimName, displayLabel, isHiddenInput, isOptional, defaultValue);
    }

    private void CredentialDialog_Load(object sender, EventArgs e) {
    }


    private void CredentialDialog_Show(object sender, EventArgs e) {
    }

    internal string GetRawInput(string claimName) {
      TextBox box = _InputBoxes.Where((b) => b.Name == claimName).FirstOrDefault();
      if(box!= null) {
        return box.Text;
      }
      return null;
    }

    internal void SetRawInput(string claimName, string value) {
      TextBox box = _InputBoxes.Where((b) => b.Name == claimName).FirstOrDefault();
      if (box != null) {
        box.Text = value;
      }
    }

    internal void DisplayError(string message) {

      //if (this.InvokeRequired) {
      //  Action i = () => this.DisplayError(message);
      //  this.Invoke(i);
      //  return;
      //}

      MessageBox.Show(this.Owner, message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

    }

    private void btnOK_Click(object sender, EventArgs e) {
      this.DialogResult = DialogResult.OK;
    }

    private void btnCancel_Click(object sender, EventArgs e) {
      this.DialogResult = DialogResult.Cancel;
    }

  }

}
