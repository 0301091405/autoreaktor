// WinForms test target for AutoReaktor: the class NecroBit decoy ctors made
// hardest (T-MAX). A form, a button, a secret revealed on click — enough
// surface for the GUI-equivalence proofs (text, child tree, click behavior).
using System;
using System.Windows.Forms;

namespace VerifyForms
{
    static class Program
    {
        const string SECRET = "VF-SECRET-4C1D";

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(SECRET));
        }
    }

    class MainForm : Form
    {
        public MainForm(string secret)
        {
            Text = "verify_forms";
            Width = 320;
            Height = 200;

            var box = new TextBox { Left = 12, Top = 12, Width = 280 };
            var button = new Button { Left = 12, Top = 44, Width = 120, Text = "reveal" };
            button.Click += (s, e) => box.Text = secret;

            Controls.Add(box);
            Controls.Add(button);
        }
    }
}
