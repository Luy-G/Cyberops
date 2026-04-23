using CyberOps.Application.Scoring;
using CyberOps.Common.Constants;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;
using Xunit;

namespace CyberOps.Tests;

// Testes de vulnerabilidade para confirmar ratios, thresholds e pesos.
public class VulnCalculationsTests
{
    // Helper para montar findings de teste de forma rapida.
    private static VulnerabilityAttackSurface Finding(VulnSeverity severity, decimal? cvss = null, bool hasExploit = false, bool isInternetExposed = false, bool isInKev = false, string? cve = null)
        => new()
        {
            FindingKey = "F-test",
            Title = "Test",
            ClientId = 1,
            SourceSystem = SourceSystem.Other,
            ScanEngine = ScanEngine.Unknown,
            Severity = severity,
            Cvss = cvss,
            HasPublicExploit = hasExploit,
            IsInternetExposed = isInternetExposed,
            IsInKevCatalog = isInKev,
            Cve = cve
        };

    [Fact]
    public void CountCriticalByCvss_ShouldCount_WhenCvssAbove9()
    {
        // CVSS 9.5 deve ser classificado como critico.
        var findings = new[] { Finding(VulnSeverity.Critical, cvss: 9.5m) };
        Assert.Equal(1, VulnCalculations.CountCriticalByCvss(findings));
    }

    [Fact]
    public void CalculateCriticalVulnsScore_ShouldReturnFullWeight_WhenRatioAbove5Percent()
    {
        // 1 critico em 10 findings => 10%, acima do threshold de 5%.
        var findings = new List<VulnerabilityAttackSurface> { Finding(VulnSeverity.Critical, cvss: 9.5m) };
        for (var i = 0; i < 9; i++) findings.Add(Finding(VulnSeverity.Medium, cvss: 5.0m));
        Assert.Equal(VulnerabilityWeights.CriticalVulns, VulnCalculations.CalculateCriticalVulnsScore(findings));
    }
    [Fact]
    public void CalculatePublicExploitScore_ShouldReturnFullWeight_WhenOneFindingHasExploit()
    {
        // Basta 1 finding com exploit publico para ativar score binario.
        var findings = new[] { Finding(VulnSeverity.High, hasExploit: true) };
        Assert.Equal(VulnerabilityWeights.PublicExploit, VulnCalculations.CalculatePublicExploitScore(findings));
    }
}
