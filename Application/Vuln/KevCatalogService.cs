using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyberOps.Application.Vuln;

// DTO minimo da resposta publica da CISA KEV feed.
public class CisaKevEntry
{
    [JsonPropertyName("cveID")]
    public string? CveId { get; set; }
}
public class CisaKevResponse
{
    [JsonPropertyName("vulnerabilities")]
    public List<CisaKevEntry>? Vulnerabilities { get; set; }
}

// Abstracao para permitir mock em testes e fallback sem rede.
public interface IKevCatalogService
{
    Task<IReadOnlySet<string>> GetKevCveIdsAsync(CancellationToken ct = default);
}
public class CisaKevCatalogService : IKevCatalogService
{
    private const string KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private readonly HttpClient _http;

    public CisaKevCatalogService(HttpClient http)
    {
        _http = http;
    }

    public async Task<IReadOnlySet<string>> GetKevCveIdsAsync(CancellationToken ct = default)
    {
        // Busca feed oficial CISA e devolve conjunto de CVE IDs normalizados.
        // O uso de HashSet acelera consultas Contains no mapper.
        var response = await _http.GetStringAsync(KevUrl, ct);
        var catalog = JsonSerializer.Deserialize<CisaKevResponse>(response);

        return (catalog?.Vulnerabilities ?? [])
            .Where(v => !string.IsNullOrWhiteSpace(v.CveId))
            .Select(v => v.CveId!.Trim().ToUpperInvariant())
            .ToHashSet();
    }
}
