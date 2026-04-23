namespace CyberOps.Application.ITSM;

// Validador do DTO ITSM da Sogilub.
// Objetivo: bloquear entradas que quebram calculo ou qualidade de dados.
public static class SogilubItsmValidator
{
    public static IReadOnlyList<string> Validate(SogilubItsmDto dto)
    {
        var errors = new List<string>();

        // Campos obrigatorios de identificacao/rastreabilidade.
        if (string.IsNullOrWhiteSpace(dto.Key))
            errors.Add("Ticket Key is required.");

        if (!dto.IssueId.HasValue || dto.IssueId.Value <= 0)
            errors.Add("Issue ID is required and must be greater than 0.");

        if (string.IsNullOrWhiteSpace(dto.CurrentStatus))
            errors.Add("Current Status is required.");

        if (string.IsNullOrWhiteSpace(dto.Summary))
            errors.Add("Summary is required.");

        // Data de criacao e base para validacoes temporais.
        if (!dto.Created.HasValue)
            errors.Add("Created date is required.");

        // Integridade numerica.
        if (dto.TimeSpentHours.HasValue && dto.TimeSpentHours.Value < 0)
            errors.Add("Time spent cannot be negative.");

        // Integridade cronologica.
        if (dto.Resolved.HasValue && dto.Created.HasValue && dto.Resolved.Value < dto.Created.Value)
            errors.Add("Resolved cannot be before Created.");

        if (dto.Updated.HasValue && dto.Created.HasValue && dto.Updated.Value < dto.Created.Value)
            errors.Add("Updated cannot be before Created.");

        return errors;
    }
}
