using System.Globalization;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;

namespace CyberOps.Application.Vuln;

// Mapper de vulnerabilidades:
// transforma campos externos em enums/valores internos consistentes.
public static class SogilubVulnMapper
{
    // Normaliza severidade textual para enum interno.
    public static VulnSeverity MapSeverity(string? raw) => raw?.Trim().ToUpperInvariant() switch
    {
        "CRITICAL" => VulnSeverity.Critical,
        "HIGH" => VulnSeverity.High,
        "MEDIUM" => VulnSeverity.Medium,
        "LOW" => VulnSeverity.Low,
        "INFO" => VulnSeverity.Info,
        _ => VulnSeverity.Unknown
    };

    // CVSS no JSON pode vir vazio/N-A/texto invalido.
    // Este parse devolve null nesses casos, evitando exceptions.
    public static decimal? ParseCvss(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Trim().Equals("N/A", StringComparison.OrdinalIgnoreCase))
            return null;

        return decimal.TryParse(raw, NumberStyles.Any, CultureInfo.InvariantCulture, out var result)
            ? result
            : null;
    }

    // Conversao completa DTO -> entidade de dominio usada no scoring.
    // O sinalizador IsInKevCatalog depende do enrichment opcional KEV.
    public static VulnerabilityAttackSurface Map(SogilubVulnFindingDto dto, long clientId, IReadOnlySet<string>? kevCveIds = null)
    {
        var cve = dto.Metadata?.Cve?.Trim().ToUpperInvariant();
        var isInKev = cve is not null && kevCveIds is not null && kevCveIds.Contains(cve);

        return new VulnerabilityAttackSurface
        {
            ClientId = clientId,
            FindingKey = dto.Id!.Trim(),
            SourceSystem = SourceSystem.Other,
            ScanEngine = ScanEngine.Unknown,
            Severity = MapSeverity(dto.Severity),
            Title = dto.Title!.Trim(),
            Cve = dto.Metadata?.Cve,
            Cvss = ParseCvss(dto.Metadata?.Cvss),
            Host = dto.Metadata?.Host,
            Port = dto.Metadata?.Port,
            Evidence = dto.Metadata?.Status,
            Description = dto.Description,
            Impact = dto.Impact,
            Recommendation = dto.Recommendation,
            HasPublicExploit = false,
            IsInternetExposed = false,
            IsInKevCatalog = isInKev
        };
    }
}
