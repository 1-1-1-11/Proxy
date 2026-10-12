$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$temporary = Join-Path $workspace ('.status-test-' + [Guid]::NewGuid().ToString('N'))
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$source = Join-Path $workspace 'claude-network\ClaudeStatus.cs'
# Pure status/notification regression checks: no network, mutex, tray, or installed files.
$harness = @'
using System;
using System.Collections.Generic;
using System.Drawing;
internal static class ClaudeStatusTests {
    static int assertions;
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-08T12:00:00+09:00");
    static Dictionary<string, object> State(bool ok, int failed, int successful, bool recovering) {
        return new Dictionary<string, object> {
            {"time", Now.ToString("o")}, {"mode", "rule"}, {"tun", true},
            {"fixed_ok", ok}, {"fixed_failed_count", failed},
            {"fixed_success_count", successful}, {"fixed_recovering", recovering}
        };
    }
    static ClaudeStatus.Status Read(Dictionary<string, object> state) { return ClaudeStatus.Evaluate(state, true, Now); }
    static void Equal(object expected, object actual, string name) {
        assertions++;
        if (!Object.Equals(expected, actual)) throw new Exception(name + ": expected " + expected + ", got " + actual);
    }
    static void Key(string expected, Dictionary<string, object> state, string name) { Equal(expected, Read(state).Key, name); }
    static void Notice(ClaudeStatus.NotificationPolicy policy, ClaudeStatus.Status state, ClaudeStatus.Notice expected, string name) {
        Equal(expected, policy.Next(state), name);
    }
    static int Main() {
        var healthy = Read(State(true, 0, 2, false));
        var pending = Read(State(false, 1, 0, false));
        var down = Read(State(false, 2, 0, false));
        var recovering = Read(State(true, 0, 1, true));
        Equal("claude", healthy.Key, "two successful probes ready");
        Equal("checking", pending.Key, "first failure pending");
        Equal(Color.DarkOrange, pending.Color, "pending must not be green");
        Equal("down", down.Key, "second failure confirmed");
        Equal(Color.Firebrick, down.Color, "confirmed failure red");
        Equal("recovering", recovering.Key, "first recovery stays pending");
        Equal(Color.DarkOrange, recovering.Color, "recovering must not be green");
        Key("recovering", State(true, 0, 1, false), "one success cannot be ready");
        Key("recovering", State(true, 0, 5, true), "explicit recovery flag wins");
        var state = State(true, 0, 2, false); state["tun"] = false;
        var domestic = Read(state); Equal("domestic", domestic.Key, "TUN off remains supported");
        state = State(false, 1, 0, false); state.Remove("fixed_failed_count");
        Key("checking", state, "missing failed count pending");
        state["fixed_failed_count"] = "broken"; Key("checking", state, "invalid failed count pending");
        state = State(true, 0, 2, false); state.Remove("fixed_success_count");
        Key("recovering", state, "legacy success cannot be ready");
        state["fixed_success_count"] = -2; Key("recovering", state, "negative success count pending");
        state = State(true, 0, 2, false); state.Remove("fixed_ok");
        Key("checking", state, "missing result cannot be ready");
        state = State(true, 0, 2, false); state["mode"] = "global";
        Key("abnormal", state, "global mode immediately abnormal");
        state = State(false, 1, 0, false); state["mode"] = "direct";
        Key("abnormal", state, "mode error takes priority over transient failure");
        state = State(true, 0, 2, false); state.Remove("mode"); Key("abnormal", state, "unknown mode not green");
        state = State(true, 0, 2, false); state.Remove("tun"); Key("abnormal", state, "unknown TUN not green");
        state = State(false, 1, 0, false); state["fixed_exit_blocked"] = true;
        var blocked = Read(state); Equal("blocked", blocked.Key, "IP block immediately red");
        var guard = ClaudeStatus.Evaluate(State(true, 0, 2, false), false, Now);
        Equal("guard", guard.Key, "dead guard immediately red");
        state = State(true, 0, 2, false); state["time"] = Now.AddSeconds(-121).ToString("o");
        var stale = Read(state); Equal("stale", stale.Key, "stale sample immediately red");
        state["time"] = Now.AddSeconds(-120).ToString("o"); Key("claude", state, "freshness boundary unchanged");
        state["time"] = "invalid"; Key("stale", state, "bad timestamp not green");
        state["time"] = Now.AddSeconds(60).ToString("o"); Key("stale", state, "future timestamp not green");
        Key("stale", null, "missing state not green");
        state = State(false, 1, 0, false); state["network_status"] = "waiting_for_physical_network"; state.Remove("mode");
        var offline = Read(state); Equal("offline", offline.Key, "physical offline recognized");

        var policy = new ClaudeStatus.NotificationPolicy();
        Notice(policy, healthy, ClaudeStatus.Notice.None, "healthy startup silent");
        for (int i = 0; i < 24; i++) {
            Key("checking", State(false, 1, 0, false), "UI refresh never advances probe count");
            Notice(policy, pending, ClaudeStatus.Notice.None, "same pending probe silent");
        }
        Notice(policy, recovering, ClaudeStatus.Notice.None, "transient recovery pending silent");
        Notice(policy, healthy, ClaudeStatus.Notice.None, "transient recovery complete silent");
        Notice(policy, domestic, ClaudeStatus.Notice.Changed, "intentional domestic switch confirmed once");
        Notice(policy, domestic, ClaudeStatus.Notice.None, "domestic mode not repeated");
        Notice(policy, offline, ClaudeStatus.Notice.None, "disconnected network silent");
        Notice(policy, domestic, ClaudeStatus.Notice.None, "reconnect without incident silent");
        Notice(policy, healthy, ClaudeStatus.Notice.Changed, "switch back to Claude mode confirmed once");
        Notice(policy, down, ClaudeStatus.Notice.Warning, "confirmed fault alerts");
        Notice(policy, down, ClaudeStatus.Notice.None, "repeated fault no duplicate");
        Notice(policy, recovering, ClaudeStatus.Notice.None, "announced fault recovery pending silent");
        Notice(policy, pending, ClaudeStatus.Notice.None, "new failure during recovery pending silent");
        Notice(policy, down, ClaudeStatus.Notice.None, "same unresolved fault no duplicate");
        Notice(policy, recovering, ClaudeStatus.Notice.None, "recovery retry silent");
        Notice(policy, healthy, ClaudeStatus.Notice.Recovered, "confirmed recovery one notice");
        Notice(policy, healthy, ClaudeStatus.Notice.None, "confirmed recovery not repeated");
        Notice(policy, down, ClaudeStatus.Notice.Warning, "second incident alerts");
        Notice(policy, domestic, ClaudeStatus.Notice.Recovered, "recovery into other mode reports recovery only");
        Notice(policy, domestic, ClaudeStatus.Notice.None, "recovered mode not repeated");
        foreach (var hard in new[] {guard, stale, blocked, Read(new Dictionary<string, object> {
            {"time", Now.ToString("o")}, {"mode", "global"}, {"fixed_ok", false}, {"fixed_failed_count", 1}
        })}) {
            policy = new ClaudeStatus.NotificationPolicy();
            Notice(policy, hard, ClaudeStatus.Notice.Warning, "hard fault alerts even at startup");
            Notice(policy, hard, ClaudeStatus.Notice.None, "hard fault repeated silent");
            Notice(policy, recovering, ClaudeStatus.Notice.None, "hard fault recovery pending");
            Notice(policy, domestic, ClaudeStatus.Notice.Recovered, "hard fault confirmed recovery");
        }
        Console.WriteLine("PASS: " + assertions + " status and notification assertions; no network or installed-state changes.");
        return 0;
    }
}
'@
try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $harnessPath = Join-Path $temporary 'ClaudeStatusTests.cs'
    $executable = Join-Path $temporary 'ClaudeStatusTests.exe'
    [IO.File]::WriteAllText($harnessPath, $harness, [Text.UTF8Encoding]::new($false))
    & $compiler '/nologo' '/target:exe' '/codepage:65001' '/main:ClaudeStatusTests' '/reference:System.Windows.Forms.dll' '/reference:System.Drawing.dll' '/reference:System.Web.Extensions.dll' ('/out:' + $executable) $source $harnessPath
    if ($LASTEXITCODE -ne 0) { throw 'ClaudeStatus regression harness compilation failed.' }
    & $executable
    if ($LASTEXITCODE -ne 0) { throw 'ClaudeStatus regression assertions failed.' }
} finally {
    if (Test-Path -LiteralPath $temporary) {
        $resolved = (Resolve-Path -LiteralPath $temporary).Path
        if ([IO.Path]::GetDirectoryName($resolved) -ne $workspace -or [IO.Path]::GetFileName($resolved) -notlike '.status-test-*') { throw 'Unexpected cleanup target.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
