using System.Text.Json.Serialization;

namespace CyberOps.Application.ITSM;

// DTO de entrada do JSON ITSM da Sogilub.
// Esta classe representa "como os dados chegam", antes de validar e mapear.
public class SogilubItsmDto
{
    // Chave externa do ticket (identificador funcional no sistema origem).
    [JsonPropertyName("Key")]
    public string? Key { get; set; }

    // Vem como numero no payload; depois e convertido para long na entidade interna.
    [JsonPropertyName("Issue ID")]
    public double? IssueId { get; set; }

    // Estado textual de origem, depois normalizado para enum ItsmStatus.
    [JsonPropertyName("Current Status")]
    public string? CurrentStatus { get; set; }

    // Tipo textual do ticket, depois normalizado para ItsmTicketType.
    [JsonPropertyName("Issue Type")]
    public string? IssueType { get; set; }

    // Prioridade textual, depois normalizada para PriorityLevel.
    [JsonPropertyName("Priority")]
    public string? Priority { get; set; }

    // Resolucao textual, depois normalizada para ItsmResolution.
    [JsonPropertyName("Resolution")]
    public string? Resolution { get; set; }

    // Titulo/resumo funcional do ticket.
    [JsonPropertyName("Summary")]
    public string? Summary { get; set; }

    // Texto livre original.
    [JsonPropertyName("Description")]
    public string? Description { get; set; }

    // Versao HTML da descricao, mantida para contexto.
    [JsonPropertyName("Description (HTML)")]
    public string? DescriptionHtml { get; set; }

    // Datas base para calculos temporais (MTTR e validacoes cronologicas).
    [JsonPropertyName("Created")]
    public DateTime? Created { get; set; }

    [JsonPropertyName("Updated")]
    public DateTime? Updated { get; set; }

    [JsonPropertyName("Resolved")]
    public DateTime? Resolved { get; set; }

    // Metadados de pessoas (util para drill-down na dashboard).
    // O payload original tem dois espacos apos ':'.
    [JsonPropertyName("Creator:  Name")]
    public string? CreatorName { get; set; }

    [JsonPropertyName("Creator:  Email")]
    public string? CreatorEmail { get; set; }

    [JsonPropertyName("Current Assignee:  Name")]
    public string? CurrentAssigneeName { get; set; }

    [JsonPropertyName("Current Assignee:  Email")]
    public string? CurrentAssigneeEmail { get; set; }

    [JsonPropertyName("Reporter:  Name")]
    public string? ReporterName { get; set; }

    [JsonPropertyName("Reporter:  Email")]
    public string? ReporterEmail { get; set; }

    // Campo textual do tempo de primeira resposta.
    [JsonPropertyName("Time to first response")]
    public string? TimeToFirstResponse { get; set; }

    // Janela SLA da primeira resposta.
    [JsonPropertyName("Time to first response: SLA Start date")]
    public DateTime? TimeToFirstResponseSlaStartDate { get; set; }

    [JsonPropertyName("Time to first response: SLA Complete date")]
    public DateTime? TimeToFirstResponseSlaCompleteDate { get; set; }

    // Horas gastas (base para MTTR no dominio Operational Security).
    [JsonPropertyName("Time Spent")]
    public decimal? TimeSpentHours { get; set; }

    // Vem como texto no payload; depois convertido para bool? no mapper.
    [JsonPropertyName("Time to first response: Breached?")]
    public string? FirstResponseSlaBreachedRaw { get; set; }
}

// Wrapper opcional do endpoint OData, onde os registos vem em "value".
public class SogilubItsmODataResponseDto
{
    [JsonPropertyName("value")]
    public List<SogilubItsmDto>? Value { get; set; }
}
