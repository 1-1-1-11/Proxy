using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;

// A real executable works with both Claude's BROWSER and VS Code's external opener.
// URLs travel to Python on stdin and are never written to a log or shell command.
internal static class ClaudeBrowser {
    [STAThread]
    static int Main(string[] args) {
        try {
            if (args.Length > 1) throw new Exception();
            string target = args.Length == 0 ? "https://claude.ai/login" : args[0];
            var start = new ProcessStartInfo(@"C:\Tools\Python\pythonw.exe");
            start.Arguments = "-X utf8 -B \"" + Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "browser_entry.py") + "\"";
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardInput = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            using (var process = Process.Start(start)) {
                byte[] encoded = new UTF8Encoding(false).GetBytes(target);
                process.StandardInput.BaseStream.Write(encoded, 0, encoded.Length);
                process.StandardInput.Close();
                if (!process.WaitForExit(110000)) {
                    // Only terminate this launcher's own child tree, never processes by name.
                    var stop = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "taskkill.exe"));
                    stop.Arguments = "/PID " + process.Id + " /T /F";
                    stop.UseShellExecute = false;
                    stop.CreateNoWindow = true;
                    stop.WindowStyle = ProcessWindowStyle.Hidden;
                    using (var cleanup = Process.Start(stop)) {
                        if (!cleanup.WaitForExit(5000)) cleanup.Kill();
                    }
                    if (!process.WaitForExit(2000)) process.Kill();
                    throw new Exception();
                }
                if (process.ExitCode != 0) throw new Exception();
            }
        } catch {
            MessageBox.Show("登录链接没有打开：固定出口检查没通过，或 CCBaga Proxy 还没有登记指纹浏览器入口。\n\n打开 CCBaga Proxy 查看原因，或在终端运行 claude-proxy。", "Claude 专用网络", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        // The failure is handled here. Never ask the caller to fall back to another browser.
        return 0;
    }
}
