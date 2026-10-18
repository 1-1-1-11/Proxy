using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

// Tray indicator for the Claude fixed exit. It only reads the in-use guard's state file
// (written about every 30 seconds) and its mutex; it sends no network traffic and changes nothing.
internal static class ClaudeStatus {
    const string GuardMutex = @"Local\ClashNetworkHealth-example";
    const int StaleSeconds = 120;
    static string GuardDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @".codex\CodexNetworkGuard");
    static readonly string InstallDir = AppDomain.CurrentDomain.BaseDirectory;

    internal sealed class Status {
        public string Key, Mode, Claude, Desktop, Checked, Tip;
        public Color Color;
        public string Mark;
    }

    internal enum Notice { None, Warning, Recovered, Changed }

    // Preserve an announced fault through pending samples. A one-sample wobble
    // never opens an incident and therefore cannot produce a recovery balloon.
    // A deliberate TUN switch between two usable modes is still confirmed once.
    internal sealed class NotificationPolicy {
        string announced, settled;
        internal Notice Next(Status status) {
            bool fault = status.Key == "guard" || status.Key == "stale" || status.Key == "blocked" ||
                         status.Key == "offchain" || status.Key == "abnormal" || status.Key == "desktop" ||
                         status.Key == "cowork" || status.Key == "down";
            if (fault) {
                if (announced == status.Key) return Notice.None;
                announced = status.Key;
                return Notice.Warning;
            }
            if (status.Key != "claude" && status.Key != "domestic") return Notice.None;
            bool recovered = announced != null;
            bool changed = settled != null && settled != status.Key;
            announced = null;
            settled = status.Key;
            return recovered ? Notice.Recovered : changed ? Notice.Changed : Notice.None;
        }
    }

    static bool GuardAlive() {
        Mutex existing;
        if (!Mutex.TryOpenExisting(GuardMutex, out existing)) return false;
        existing.Dispose();
        return true;
    }

    internal static Status Read() {
        Dictionary<string, object> state = null;
        try {
            state = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(GuardDir, "network-state.json")));
        } catch { state = null; }
        return Evaluate(state, GuardAlive(), DateTimeOffset.Now);
    }

    static int SampleCount(object value) {
        int count;
        return value != null && Int32.TryParse(Convert.ToString(value), out count) && count >= 0 ? count : 1;
    }

    static bool OffChain(object value) {
        int count;
        return value != null && Int32.TryParse(Convert.ToString(value), out count) && count > 0;
    }

    // Counts come from completed guard probes, never from the five-second UI timer.
    internal static Status Evaluate(Dictionary<string, object> state, bool guardAlive, DateTimeOffset now) {
        var s = new Status { Mode = "未知", Desktop = "桌面端 / 普通浏览器：保护状态未知", Checked = "没有核对记录" };
        Func<string, object> get = key => state != null && state.ContainsKey(key) ? state[key] : null;
        DateTimeOffset written;
        double age = DateTimeOffset.TryParse(get("time") as string, out written) ? (now - written).TotalSeconds : double.MaxValue;
        if (age != double.MaxValue) s.Checked = "出口核对：" + Math.Max(0, Math.Min(Int32.MaxValue, age)).ToString("0") + " 秒前";
        string mode = get("mode") as string;
        bool tun = Equals(get("tun"), true);
        if (mode == "rule" && tun) { s.Mode = "Claude 模式（虚拟网卡开）"; s.Desktop = "客户端：固定走专用端口；普通浏览器：受规则保护"; }
        else if (mode == "rule" && Equals(get("tun"), false)) { s.Mode = "国内模式（虚拟网卡关）"; s.Desktop = "客户端：固定走专用端口；普通浏览器：不受保护"; }
        else if (mode == "rule") s.Mode = "规则模式（虚拟网卡状态未知）";
        else if (mode != null) { s.Mode = "异常：Clash 在" + mode + "模式"; s.Desktop = "客户端：固定走专用端口；普通浏览器：不受保护"; }

        if (!guardAlive) Set(s, "guard", "Claude 保护异常：使用中守护没有运行", Color.Firebrick, "!");
        else if (state == null || age > StaleSeconds || age < -30) Set(s, "stale", "Claude 状态未确认：守护没有按时更新", Color.Firebrick, "!");
        else if (Equals(get("fixed_exit_blocked"), true)) Set(s, "blocked", "Claude 已阻断：固定出口 IP 不符", Color.Firebrick, "!");
        else if (OffChain(get("claude_offchain"))) Set(s, "offchain", "Claude 有连接没走固定出口：运行 claude-proxy -Watch 查看", Color.Firebrick, "!");
        else if ((get("network_status") as string) == "waiting_for_physical_network") Set(s, "offline", "等待网络：没有连接 Wi-Fi / 网线", Color.Gray, "…");
        else if (mode != "rule" || !(get("tun") is bool)) Set(s, "abnormal", mode == "rule" || mode == null ? "Clash 模式未确认：桌面端 / 普通浏览器保护状态未知" : "Clash 不在规则模式：桌面端 / 普通浏览器不受保护", Color.Firebrick, "!");
        else if (!String.IsNullOrEmpty(get("desktop_unprotected") as string)) Set(s, "desktop", "客户端没受保护，已被关闭：见弹窗或运行 claude-proxy", Color.Firebrick, "!");
        else if (!String.IsNullOrEmpty(get("cowork_unprotected") as string)) Set(s, "cowork", "Cowork 服务没有断网：运行 claude-proxy -Protect", Color.Firebrick, "!");
        else if (!Equals(get("fixed_ok"), true)) {
            if (SampleCount(get("fixed_failed_count")) >= 2) Set(s, "down", "固定出口连续检测失败", Color.Firebrick, "!");
            else Set(s, "checking", "出口暂未确认，正在复查", Color.DarkOrange, "…");
        }
        else if (Equals(get("fixed_recovering"), true) || SampleCount(get("fixed_success_count")) < 2) Set(s, "recovering", "出口检测已通过，正在确认稳定", Color.DarkOrange, "…");
        else if (mode == "rule" && tun) Set(s, "claude", "Claude 可用：CLI / VS Code / 专用浏览器 / 客户端", Color.ForestGreen, "C");
        else if (mode == "rule") Set(s, "domestic", "Claude 可用：CLI / VS Code / 专用浏览器 / 客户端", Color.RoyalBlue, "国");
        string head = s.Key == "claude" ? "Claude 模式" : s.Key == "domestic" ? "国内模式" : "注意";
        s.Tip = head + "\n" + s.Claude;
        if (s.Tip.Length > 63) s.Tip = s.Tip.Substring(0, 63);
        return s;
    }

    static void Set(Status s, string key, string claude, Color color, string mark) {
        s.Key = key; s.Claude = claude; s.Color = color; s.Mark = mark;
    }

    [DllImport("user32.dll")]
    static extern bool DestroyIcon(IntPtr handle);

    static Icon Draw(Status s) {
        using (var bitmap = new Bitmap(16, 16))
        using (var g = Graphics.FromImage(bitmap))
        using (var brush = new SolidBrush(s.Color))
        using (var font = new Font(s.Mark == "国" ? "Microsoft YaHei" : "Segoe UI", s.Mark == "国" ? 7.5f : 8.5f, FontStyle.Bold, GraphicsUnit.Point))
        using (var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center }) {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
            g.FillEllipse(brush, 0, 0, 15, 15);
            g.DrawString(s.Mark, font, Brushes.White, new RectangleF(0, 0, 16, 16), format);
            // FromHandle does not own the HICON. Keep an owned copy and release
            // the original, preserving the fix already present in the installed build.
            IntPtr handle = bitmap.GetHicon();
            try { using (var borrowed = Icon.FromHandle(handle)) return (Icon)borrowed.Clone(); }
            finally { DestroyIcon(handle); }
        }
    }

    static void Start(string file, string arguments) {
        try { Process.Start(new ProcessStartInfo(file, arguments) { UseShellExecute = true }); }
        catch { MessageBox.Show("无法启动：" + file, "Claude 状态", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    [STAThread]
    static int Main(string[] args) {
        if ((args.Length == 2 || args.Length == 3) && args[0] == "--once") {
            // Verification hook: write the computed status, then exit without showing an icon.
            if (args.Length == 3) GuardDir = args[2];
            var s = Read();
            File.WriteAllText(args[1], s.Key + "\n" + s.Mode + "\n" + s.Claude + "\n" + s.Desktop + "\n" + s.Checked, new System.Text.UTF8Encoding(false));
            return 0;
        }
        bool created;
        using (var single = new Mutex(true, @"Local\ClaudeStatusTray-example", out created)) {
            if (!created) return 0;
            Application.EnableVisualStyles();
            var icon = new NotifyIcon { Visible = true };
            var menu = new ContextMenuStrip();
            var modeItem = new ToolStripMenuItem { Enabled = false };
            var claudeItem = new ToolStripMenuItem { Enabled = false };
            var desktopItem = new ToolStripMenuItem { Enabled = false };
            var checkedItem = new ToolStripMenuItem { Enabled = false };
            menu.Items.AddRange(new ToolStripItem[] { modeItem, claudeItem, desktopItem, checkedItem, new ToolStripSeparator() });
            menu.Items.Add("切换模式：打开 Clash Verge（托盘开关「虚拟网卡模式」）", null, (o, e) => Start(@"C:\Tools\ClashVerge\clash-verge.exe", ""));
            menu.Items.Add("检查 Claude 能否使用", null, (o, e) => Start(Path.Combine(InstallDir, "Network-Check.cmd"), ""));
            menu.Items.Add("看看 Claude 连了哪里（5 分钟）", null, (o, e) => Start("powershell.exe",
                "-NoExit -NoProfile -ExecutionPolicy Bypass -File \"" + Path.Combine(InstallDir, "Repair-ClaudeProxy.ps1") + "\" -Watch"));
            menu.Items.Add("打开 Claude 专用浏览器", null, (o, e) => Start(Path.Combine(InstallDir, "ClaudeBrowser.exe"), ""));
            menu.Items.Add("打开 Claude 客户端（固定出口）", null, (o, e) => Start(Path.Combine(InstallDir, "Open-ClaudeDesktop.cmd"), ""));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("退出状态图标", null, (o, e) => { icon.Visible = false; Application.Exit(); });
            icon.ContextMenuStrip = menu;
            var notifications = new NotificationPolicy();
            string drawn = null;
            Icon current = null;
            Action refresh = () => {
                var s = Read();
                modeItem.Text = "当前：" + s.Mode;
                claudeItem.Text = s.Claude;
                desktopItem.Text = s.Desktop;
                checkedItem.Text = s.Checked;
                icon.Text = s.Tip;
                string visual = s.Color.ToArgb() + ":" + s.Mark;
                if (drawn != visual) {
                    var next = Draw(s);
                    icon.Icon = next;
                    if (current != null) current.Dispose();
                    current = next;
                    drawn = visual;
                }
                var notice = notifications.Next(s);
                if (notice != Notice.None) icon.ShowBalloonTip(8000, notice == Notice.Warning ? "Claude 状态：需要处理" :
                    notice == Notice.Recovered ? "Claude 状态：出口已恢复" : "Claude 状态已变化",
                    s.Mode + "\n" + s.Claude, notice == Notice.Warning ? ToolTipIcon.Warning : ToolTipIcon.Info);
            };
            var timer = new System.Windows.Forms.Timer { Interval = 5000 };
            timer.Tick += (o, e) => refresh();
            icon.MouseClick += (o, e) => { if (e.Button == MouseButtons.Left) refresh(); };
            refresh();
            timer.Start();
            Application.Run();
            timer.Dispose();
            icon.Dispose();
            if (current != null) current.Dispose();
            menu.Dispose();
        }
        return 0;
    }
}
