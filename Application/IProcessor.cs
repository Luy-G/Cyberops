using CyberOps.Application.Scoring;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;

namespace CyberOps.Application.Contracts.Processing;

// Contrato do pipeline principal:
// recebe input bruto/configurado e devolve dados processados + scores.
public interface IProcessor
{
    Task<ProcessorResult> ProcessAsync(ProcessorInput input);
}


// Input unico do processamento por cliente.
// ActiveDomains permite calcular apenas o que faz sentido para cada cobertura.
public class ProcessorInput
{
    public required long ClientId { get; init; }
    public IReadOnlyList<IDomain> ActiveDomains { get; init; } = [];
    public string? ItsmJson { get; init; }
    public string? VulnJson { get; init; }
    public ClientItsmCalcs? ItsmCalcs { get; init; }
    public ClientVulnCalcs? VulnCalcs { get; init; }
}

// Output padrao para consumo por camadas acima (API, export, dashboard prep).
// Inclui dados normalizados, erros de ingestao e resultados de scoring.
public class ProcessorResult
{
    public bool Success { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = [];
    public IReadOnlyList<Operationalsecitsm> ItsmTickets { get; init; } = [];
    public IReadOnlyList<VulnerabilityAttackSurface> VulnFindings { get; init; } = [];
    public IReadOnlyDictionary<DomainKey, decimal> DomainScores { get; init; } = new Dictionary<DomainKey, decimal>();
    public decimal CompositeScore { get; init; }
}
