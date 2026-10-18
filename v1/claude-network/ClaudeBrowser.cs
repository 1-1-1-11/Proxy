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
            MessageBox.Show("专用浏览器未打开：代理或 WebRTC 保护检查未通过，或已有浏览器配置冲突。\n\n请运行 claude-proxy -Full 查看原因。claude-proxy -Repair 只修复受管理的代理配置，不会自动改 Chrome 全局策略。", "Claude 专用网络", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        // The failure is handled here. Never ask the caller to fall back to another browser.
        return 0;
    }
}
