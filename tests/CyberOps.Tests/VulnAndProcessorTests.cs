using CyberOps.Application.Contracts.Processing;
using CyberOps.Application.ITSM;
using CyberOps.Application.Processors;
using CyberOps.Application.Scoring;
using CyberOps.Application.Vuln;
using CyberOps.Domain.Enums;

namespace CyberOps.Tests;

public class VulnAndProcessorTests
{
    [Fact]
    public async Task VulnIngestion_ShouldParseFindings_AndApplyKevFlag()
    {
        const string json = """
        {
          "vulnerability_findings": [
            {
              "id": "F-01",
              "severity": "CRITICAL",
              "title": "Critical finding",
              "metadata": {
                "CVE": "CVE-2026-9999",
                "CVSS": "9.8",
                "Host": "172.23.1.20",
                "Port": "1433/tcp",
                "Status": "CONFIRMED"
              },
              "description": "d",
              "impact": "i",
              "recommendation": "r"
            },
            {
              "id": "F-02",
              "severity": "HIGH",
              "title": "High finding",
              "metadata": {
                "CVSS": "N/A"
              },
              "description": "d",
              "impact": "i",
              "recommendation": "r"
            }
          ]
        }
        """;

        var ingestion = new SogilubVulnIngestion(new FakeKevCatalogService(new HashSet<string> { "CVE-2026-9999" }));
        var result = await ingestion.IngestAsync(json, clientId: 7);

        Assert.Empty(result.Errors);
        Assert.Equal(2, result.Items.Count);

        var first = result.Items[0];
        Assert.Equal(VulnSeverity.Critical, first.Severity);
        Assert.Equal(9.8m, first.Cvss);
        Assert.True(first.IsInKevCatalog);

        var second = result.Items[1];
        Assert.Null(second.Cvss);
    }

    [Fact]
    public async Task Processor_ShouldCalculateDomainScores_AndComposite()
    {
        const string itsmJson = """
        {
          "value": [
            {
              "Key": "SR-1",
              "Issue ID": 1,
              "Current Status": "Closed",
              "Summary": "Done one",
              "Created": "2026-03-10T09:38:45.271Z",
              "Time Spent": 8,
              "Time to first response: Breached?": "false"
            },
            {
              "Key": "SR-2",
              "Issue ID": 2,
              "Current Status": "In Progress",
              "Summary": "Open one",
              "Created": "2026-03-10T09:38:45.271Z"
            }
          ]
        }
        """;

        const string vulnJson = """
        {
          "vulnerability_findings": [
            {
              "id": "F-1",
              "severity": "HIGH",
              "title": "Finding",
              "metadata": {
                "CVE": "CVE-2026-1000",
                "CVSS": "8.1",
                "Host": "172.23.1.45",
                "Port": "1433/tcp",
                "Status": "CONFIRMED"
              },
              "description": "d",
              "impact": "i",
              "recommendation": "r"
            }
          ]
        }
        """;

        var processor = new SimpleScoreProcessor(new SogilubItsmIngestion(), new SogilubVulnIngestion());

        var result = await processor.ProcessAsync(new ProcessorInput
        {
            ClientId = 99,
            ItsmJson = itsmJson,
            VulnJson = vulnJson,
            ItsmCalcs = new CyberOps.Domain.Entities.ClientItsmCalcs
            {
                ClientId = 99,
                OpenTicketsBestMax = 1,
                OpenTicketsMediumMax = 3,
                MttrTargetHours = 5
            }
        });

        Assert.True(result.Success, string.Join(" | ", result.Errors));
        Assert.Equal(2, result.ItsmTickets.Count);
        Assert.Single(result.VulnFindings);
        Assert.True(result.DomainScores.ContainsKey(DomainKey.OperationalSecurity));
        Assert.True(result.DomainScores.ContainsKey(DomainKey.VulnerabilityAndAttackSurface));
        Assert.InRange(result.CompositeScore, 0m, 1m);
    }

    [Fact]
    public async Task VulnIngestion_ShouldReturnError_WhenJsonInvalid()
    {
        var ingestion = new SogilubVulnIngestion();
        var result = await ingestion.IngestAsync("not json", clientId: 1);

        Assert.Empty(result.Items);
        Assert.Contains(result.Errors, e => e.StartsWith("Invalid Vulnerability JSON:"));
    }

    [Fact]
    public void LocalItsmJson_SmokeTest_WhenFileExists_ShouldDeserializeAndMap()
    {
        var path = Environment.GetEnvironmentVariable("CYBEROPS_ITSM_JSON")
            ?? @"c:\Users\luisn\Desktop\itsm.json";

        if (!File.Exists(path))
            return;

        var json = File.ReadAllText(path);
        var result = new SogilubItsmIngestion().Ingest(json, clientId: 1);

        Assert.True(result.Items.Count > 0, "ITSM ingestou 0 items. Primeiro erro: " + (result.Errors.FirstOrDefault() ?? "(sem erros)"));
        Assert.DoesNotContain(result.Errors, e => e.StartsWith("Invalid ITSM JSON:"));
    }

    [Fact]
    public async Task LocalVulnsJson_SmokeTest_WhenFileExists_ShouldDeserializeAndMap()
    {
        var path = Environment.GetEnvironmentVariable("CYBEROPS_VULNS_JSON")
            ?? @"c:\Users\luisn\Downloads\vulns.json";

        if (!File.Exists(path))
            return;

        var json = File.ReadAllText(path);
        var result = await new SogilubVulnIngestion().IngestAsync(json, clientId: 1);

        Assert.True(result.Items.Count > 0, "Vulns ingestou 0 items. Primeiro erro: " + (result.Errors.FirstOrDefault() ?? "(sem erros)"));
        Assert.DoesNotContain(result.Errors, e => e.StartsWith("Invalid Vulnerability JSON:"));
    }

    private sealed class FakeKevCatalogService(IReadOnlySet<string> cves) : IKevCatalogService
    {
        public Task<IReadOnlySet<string>> GetKevCveIdsAsync(CancellationToken ct = default)
            => Task.FromResult(cves);
    }
}
