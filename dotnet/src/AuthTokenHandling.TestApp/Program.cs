using System;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyMetadata("SourceContext", "AuthTokenHandling.TestApp")]

namespace AuthTokenHandling.TestApp {

	static class Program {

		/// <summary>
		/// The main entry point for the application (WebView2 based test client).
		/// </summary>
		[STAThread]
		static void Main() {

			Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);

			Application.Run(new MainForm());

		}

	}

}
