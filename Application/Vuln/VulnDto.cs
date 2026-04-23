using System.Text.Json.Serialization;

namespace CyberOps.Application.Vuln;

// Bloco de metadados tecnicos de um finding.
// Reflete o payload da fonte e e usado no mapeamento para entidade interna.
public class SogilubVulnMetadataDto
{
    // CVE textual (ex: CVE-2024-12345), usado para coverage e enrichment KEV.
    [JsonPropertyName("CVE")]
    public string? Cve { get; set; }

    // CVSS textual de origem; o parser converte para decimal? no mapper.
    [JsonPropertyName("CVSS")]
    public string? Cvss { get; set; }

    // Contexto tecnico do ativo afetado.
    [JsonPropertyName("Host")]
    public string? Host { get; set; }
    [JsonPropertyName("Port")]
    public string? Port { get; set; }
    [JsonPropertyName("Status")]
    public string? Status { get; set; }
}

// DTO de cada finding vindo do report.
public class SogilubVulnFindingDto
{
    // Identificador unico do finding no sistema origem.
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    // Severidade textual antes da normalizacao para enum.
    [JsonPropertyName("severity")]
    public string? Severity { get; set; }
    // Titulo curto da vulnerabilidade.
    [JsonPropertyName("title")]
    public string? Title { get; set; }
    // Subobjeto de metadados (CVE/CVSS/host/port).
    [JsonPropertyName("metadata")]
    public SogilubVulnMetadataDto? Metadata { get; set; }
    // Campos descritivos para contexto analitico.
    [JsonPropertyName("description")]
    public string? Description { get; set; }
    [JsonPropertyName("impact")]
    public string? Impact { get; set; }
    [JsonPropertyName("recommendation")]
    public string? Recommendation { get; set; }
}

// Objeto raiz do JSON de vulnerabilidades da Sogilub.
// Contem a colecao que sera percorrida na ingestao.
public class SogilubVulnReportDto
{
    [JsonPropertyName("vulnerability_findings")]
    public List<SogilubVulnFindingDto>? vulnerability_findings { get; set; }
}
