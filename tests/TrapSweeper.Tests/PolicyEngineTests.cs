using TrapSweeper.Core.Policy;
using Xunit;

namespace TrapSweeper.Tests;

public class PolicyEngineTests
{
    private static (PolicyEngine Engine, InMemoryRegistryStore Store) NewEngine()
    {
        var store = new InMemoryRegistryStore();
        return (new PolicyEngine(store), store);
    }

    [Fact]
    public void Audit_NotConfigured_WhenRegistryEmpty()
    {
        var (engine, _) = NewEngine();
        var result = engine.Audit(PolicyEngine.Profile.Balanced);
        Assert.All(result.Checks, c => Assert.Equal(PolicyState.NotConfigured, c.State));
    }

    [Fact]
    public void Audit_Compliant_WhenExpectedValuePresent()
    {
        var (engine, store) = NewEngine();
        store.SetDword(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4);
        var result = engine.Audit(PolicyEngine.Profile.Balanced);
        Assert.Contains(result.Checks, c => c.Id == "SMB-03" && c.State == PolicyState.Compliant);
    }

    [Fact]
    public void Audit_DetectsNonCompliantValue()
    {
        var (engine, store) = NewEngine();
        store.SetDword(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 1);
        var result = engine.Audit(PolicyEngine.Profile.Balanced);
        Assert.Contains(result.Checks, c => c.Id == "NAME-01" && c.State == PolicyState.NonCompliant);
    }

    [Fact]
    public void Apply_DryRun_DoesNotWrite()
    {
        var (engine, store) = NewEngine();
        var (changes, _) = engine.Apply(PolicyEngine.Profile.Balanced, dryRun: true, null, "/tmp/backup");
        Assert.NotEmpty(changes);
        Assert.DoesNotContain(store.Keys, k => k.Value.Count > 0);
    }

    [Fact]
    public void Apply_ForReal_WritesExpectedDwordsAndBacksUp()
    {
        var (engine, store) = NewEngine();
        var backupDir = Path.Combine(Path.GetTempPath(), "ts-policy-test-" + Guid.NewGuid().ToString("N"));
        var (changes, warnings) = engine.Apply(PolicyEngine.Profile.Strict, dryRun: false,
            new[] { "nas01.corp.local", "print01" }, backupDir);

        Assert.NotEmpty(changes);
        var after = engine.Audit(PolicyEngine.Profile.Strict);
        Assert.Equal(after.Checks.Count, after.Compliant);
        Assert.NotEmpty(store.BackupCalls);
        Assert.Contains(warnings, w => w.Contains("NTLM 出站例外"));
    }

    [Fact]
    public void ExportReg_ContainsAllSpecsAndDwordSyntax()
    {
        var (engine, _) = NewEngine();
        var reg = engine.ExportRegFile(PolicyEngine.Profile.Balanced);
        Assert.StartsWith("Windows Registry Editor Version 5.00", reg);
        Assert.Contains("\"RestrictSendingNTLMTraffic\"=dword:00000002", reg);
        Assert.Contains("\"EnableMulticast\"=dword:00000000", reg);
        Assert.Contains("mrxsmb10", reg);
    }

    [Fact]
    public void ExportFirewall_AllowsInternalBeforeBlocking()
    {
        var script = PolicyEngine.ExportFirewallScript(new[] { "10.0.0.0/8" });
        Assert.Contains("10.0.0.0/8", script);
        Assert.Contains("action=allow", script);
        Assert.Contains("action=block", script);
        Assert.Contains("445", script);
        // 放行规则必须先于阻断规则生成
        Assert.True(script.IndexOf("action=allow", StringComparison.Ordinal) <
                    script.IndexOf("action=block", StringComparison.Ordinal));
    }

    [Fact]
    public void AuditProfile_AuditModeUsesWeakerNtlmTarget()
    {
        var (engine, store) = NewEngine();
        store.SetDword(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic", 1);
        var audit = engine.Audit(PolicyEngine.Profile.Audit);
        Assert.Contains(audit.Checks, c => c.Id == "NTLM-01" && c.State == PolicyState.Compliant);

        var balanced = engine.Audit(PolicyEngine.Profile.Balanced);
        Assert.Contains(balanced.Checks, c => c.Id == "NTLM-01" && c.State == PolicyState.NonCompliant);
    }
}
