namespace CyberOps.Application.Vuln;

// Validador minimo dos findings de vulnerabilidade.
// Objetivo: impedir entrada sem identificacao basica para scoring/rastreio.
public static class SogilubVulnValidator
{
    public static IReadOnlyList<string> Validate(SogilubVulnFindingDto dto)
    {
        var errors = new List<string>();

        // Sem Id nao e possivel identificar unicamente o finding.
        if (string.IsNullOrWhiteSpace(dto.Id))
            errors.Add("Finding Id is required.");

        // Sem titulo o finding perde legibilidade para analise e dashboard.
        if (string.IsNullOrWhiteSpace(dto.Title))
            errors.Add("Finding Title is required.");

        // Nao lanca exception: devolve todos os erros para tratamento em lote.
        return errors;
    }
}
