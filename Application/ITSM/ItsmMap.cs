using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;

namespace CyberOps.Application.ITSM;

// Mapper ITSM:
// transforma DTO da fonte em entidade interna padronizada para calculo.
public static class SogilubItsmMapper
{
    public static Operationalsecitsm Map(SogilubItsmDto dto, long clientId)
    {
        // Conversao 1:1 com normalizacao de enums e limpeza de campos.
        return new Operationalsecitsm
        {
            ClientId = clientId,
            SourceSystem = SourceSystem.Jira,
            TicketKey = dto.Key!.Trim(),
            IssueId = Convert.ToInt64(dto.IssueId!.Value),
            Status = MapStatus(dto.CurrentStatus),
            TicketType = MapTicketType(dto.IssueType),
            Priority = MapPriority(dto.Priority),
            Resolution = MapResolution(dto.Resolution),
            Title = dto.Summary!.Trim(),
            Description = dto.Description,
            DescriptionHtml = dto.DescriptionHtml,
            CreatedAt = dto.Created!.Value,
            UpdatedAt = dto.Updated,
            ResolvedAt = dto.Resolved,
            CreatorName = dto.CreatorName,
            CreatorEmail = dto.CreatorEmail,
            CurrentAssigneeName = dto.CurrentAssigneeName,
            CurrentAssigneeEmail = dto.CurrentAssigneeEmail,
            ReporterName = dto.ReporterName,
            ReporterEmail = dto.ReporterEmail,
            FirstResponseDurationText = dto.TimeToFirstResponse,
            FirstResponseSlaStartAt = dto.TimeToFirstResponseSlaStartDate,
            FirstResponseSlaCompleteAt = dto.TimeToFirstResponseSlaCompleteDate,
            FirstResponseSlaBreached = ParseNullableBoolean(dto.FirstResponseSlaBreachedRaw),
            TimeSpentHours = dto.TimeSpentHours
        };
    }

    // Alguns campos booleanos chegam como texto ("true"/"false").
    // Este helper converte para bool? para representar tambem "desconhecido".
    private static bool? ParseNullableBoolean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return value.Trim().ToLowerInvariant() switch
        {
            "true" => true,
            "false" => false,
            _ => null
        };
    }

    // Normaliza status textual para enum interna usada nos filtros de score.
    public static ItsmStatus MapStatus(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "new" => ItsmStatus.New,
        "open" => ItsmStatus.Open,
        "triaged" => ItsmStatus.Triaged,
        "in progress" => ItsmStatus.InProgress,
        "pending" => ItsmStatus.Pending,
        "on hold" => ItsmStatus.OnHold,
        "resolved" => ItsmStatus.Resolved,
        "closed" => ItsmStatus.Closed,
        "cancelled" => ItsmStatus.Cancelled,
        "reopened" => ItsmStatus.Reopened,
        _ => ItsmStatus.Unknown
    };

    // Normaliza tipo textual de ticket para enum.
    public static ItsmTicketType MapTicketType(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "incident" => ItsmTicketType.Incident,
        "task" => ItsmTicketType.Task,
        "subtask" => ItsmTicketType.Subtask,
        "sub-task" => ItsmTicketType.Subtask,
        "service request" => ItsmTicketType.ServiceRequest,
        "problem" => ItsmTicketType.Problem,
        "change" => ItsmTicketType.Change,
        "case" => ItsmTicketType.Case,
        null or "" => ItsmTicketType.Unknown,
        _ => ItsmTicketType.Other
    };

    // Normaliza prioridade textual para enum.
    public static PriorityLevel MapPriority(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "p1 (critical)" => PriorityLevel.Critical,
        "p2 (urgent)" => PriorityLevel.High,
        "p3 (normal)" => PriorityLevel.Medium,
        "p4 (low)" => PriorityLevel.Low,
        "low" => PriorityLevel.Low,
        "medium" => PriorityLevel.Medium,
        "high" => PriorityLevel.High,
        "critical" => PriorityLevel.Critical,
        _ => PriorityLevel.Unknown
    };

    // Normaliza resolucao textual para enum.
    public static ItsmResolution MapResolution(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        null or "" => ItsmResolution.None,
        "done" => ItsmResolution.Done,
        "resolved" => ItsmResolution.Resolved,
        "fixed" => ItsmResolution.Fixed,
        "workaround" => ItsmResolution.Workaround,
        "duplicate" => ItsmResolution.Duplicate,
        "won't fix" => ItsmResolution.WontFix,
        "wontfix" => ItsmResolution.WontFix,
        "not reproducible" => ItsmResolution.NotReproducible,
        "cancelled" => ItsmResolution.Cancelled,
        "rejected" => ItsmResolution.Rejected,
        _ => ItsmResolution.Unknown
    };
}
