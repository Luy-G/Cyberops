using System.Text.Json;
using CyberOps.Application.Ingestion;
using CyberOps.Domain.Entities;

namespace CyberOps.Application.Vuln;

// Ingestor especifico do formato Sogilub para Vulnerability.
// Papel: JSON bruto -> DTO -> validacao -> entidade interna normalizada.
public class SogilubVulnIngestion
{
    private readonly IKevCatalogService? _kevCatalogService;

    public SogilubVulnIngestion(IKevCatalogService? kevCatalogService = null)
    {
        _kevCatalogService = kevCatalogService;
    }

    public async Task<IngestionResult<VulnerabilityAttackSurface>> IngestAsync(string json, long clientId, CancellationToken ct = default)
    {
        // Erros e itens sao separados para permitir processamento parcial.
        var errors = new List<string>();
        var items = new List<VulnerabilityAttackSurface>();

        SogilubVulnReportDto? report;
        try
        {
            report = JsonSerializer.Deserialize<SogilubVulnReportDto>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }
        catch (Exception ex)
        {
            // Erro estrutural de JSON: nao e possivel continuar.
            return new IngestionResult<VulnerabilityAttackSurface>
            {
                Errors = [$"Invalid Vulnerability JSON: {ex.Message}"]
            };
        }
         if (report is null)
        {
            return new IngestionResult<VulnerabilityAttackSurface>
            {
                Errors = ["Vulnerability JSON is empty or invalid."]
            };
        }

        IReadOnlySet<string>? kevCveIds = null;
        if (_kevCatalogService is not null)
        {
            try
            {
                // Opcional: enriquece findings com informacao KEV (CISA).
                kevCveIds = await _kevCatalogService.GetKevCveIdsAsync(ct);
            }
            catch (Exception ex)
            {
                // Falha no KEV nao deve bloquear ingestao principal.
                errors.Add($"Could not load KEV catalog: {ex.Message}");
            }
        }
         var findings = report.vulnerability_findings ?? [];
        for (var i = 0; i < findings.Count; i++)
        {
            var dto = findings[i];
            var validationErrors = SogilubVulnValidator.Validate(dto);
            if (validationErrors.Count > 0)
            {
                // Mantem indice da linha para diagnostico facil.
                errors.AddRange(validationErrors.Select(e => $"Vuln row {i + 1}: {e}"));
                continue;
            }

            // Conversao final para entidade que o motor de scoring entende.
            items.Add(SogilubVulnMapper.Map(dto, clientId, kevCveIds));
        }
        return new IngestionResult<VulnerabilityAttackSurface>
        {
            Items = items,
            Errors = errors
        };
    }
}
