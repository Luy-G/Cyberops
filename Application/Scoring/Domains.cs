using CyberOps.Common.Constants;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;
using NCalc;

namespace CyberOps.Application.Scoring;

// Cada dominio sabe calcular o seu proprio score.
// O processor principal recebe uma lista de dominios ativos e chama Calculate(...)
// para cada um deles.
public interface IDomain
{
    DomainKey Key { get; }
    decimal Weight { get; }
    decimal Calculate(DomainContext context);
}

// Pesos globais dos 7 dominios da dashboard.
// Estes valores representam importancia relativa no score composto final.
public static class DomainWeights
{
    public const decimal ThreatLandscape = 0.18m;
    public const decimal VulnerabilityAndAttackSurface = 0.18m;
    public const decimal DetectionAndResponse = 0.18m;
    public const decimal IdentityAndAccessSecurity = 0.14m;
    public const decimal GovernanceAndResilience = 0.12m;
    public const decimal OperationalSecurity = 0.10m;
    public const decimal HumanRisk = 0.10m;
}

// Contexto minimo que um dominio precisa para calcular:
// dados ingeridos (tickets/findings) + configuracoes de calculo por cliente.
// Esta classe e partilhada entre todos os dominios para simplificar o contrato.
public class DomainContext
{
    public required long ClientId { get; init; }
    public IReadOnlyList<Operationalsecitsm> ItsmTickets { get; init; } = [];
    public IReadOnlyList<VulnerabilityAttackSurface> VulnFindings { get; init; } = [];
    public ClientItsmCalcs? ItsmCalcs { get; init; }
    public ClientVulnCalcs? VulnCalcs { get; init; }
}

// Wrapper simples para NCalc.
// A ideia e receber uma formula em texto + parametros ja preparados e obter o valor final.
// Isto concretiza o padrao "PreCalc primeiro, formula depois".
public static class NCalcEvaluator
{
    public static decimal Evaluate(string expression, Dictionary<string, object> parameters)
    {
        var evaluator = new Expression(expression);

        foreach (var (key, value) in parameters)
        {
            evaluator.Parameters[key] = value;
        }

        return Convert.ToDecimal(evaluator.Evaluate());
    }
}

public class OperationalSecurityDomain : IDomain
{
    public DomainKey Key => DomainKey.OperationalSecurity;
    public decimal Weight => DomainWeights.OperationalSecurity;

    private static readonly IReadOnlyList<(IMetric Metric, decimal Weight)> Metrics =
    [
        // Cada metrica expone uma expression NCalc (definida em Domain/Entity.cs).
        // Aqui so compomos a lista de metricas ativas e o peso interno de cada uma.
        (new OpenTicketsMetric(), OperationalSecurityWeights.OpenTickets),
        (new MttrMetric(), OperationalSecurityWeights.Mttr),
        (new SlaComplianceMetric(), OperationalSecurityWeights.SlaCompliance),
    ];

    public decimal Calculate(DomainContext context)
    {
        // Sem dados ITSM nao ha como calcular Operational Security.
        if (context.ItsmCalcs is null || !context.ItsmTickets.Any())
        {
            return 0m;
        }

        // 1) Prepara variaveis simples (contagens/ratios/medias).
        var parameters = PreCalc(context);

        // 2) Aplica formula de cada metrica via NCalc.
        var weighted = Metrics.Sum(metric =>
            NCalcEvaluator.Evaluate(metric.Metric.Expression, parameters) * metric.Weight);

        // 3) Normaliza pelo peso total ativo para score final do dominio.
        return weighted / OperationalSecurityWeights.TotalActiveWeight;
    }

    private static Dictionary<string, object> PreCalc(DomainContext context)
    {
        // PreCalc concentra toda preparacao de dados para evitar expressions complexas.
        var tickets = context.ItsmTickets;

        var openTickets = tickets.Count(t => t.Status == ItsmStatus.InProgress);

        var closedWithHours = tickets
            .Where(t => t.Status == ItsmStatus.Closed && t.TimeSpentHours.HasValue)
            .ToList();

        var mttr = closedWithHours.Count == 0
            ? 0m
            : closedWithHours.Average(t => t.TimeSpentHours!.Value);

        var closedWithSla = tickets
            .Where(t => t.Status == ItsmStatus.Closed && t.FirstResponseSlaBreached.HasValue)
            .ToList();

        var slaCompliance = closedWithSla.Count == 0
            ? 0m
            : (decimal)closedWithSla.Count(t => t.FirstResponseSlaBreached == false) / closedWithSla.Count;

        // Parametros usados pelas expressions OpenTicketsMetric/MttrMetric/SlaComplianceMetric.
        // NCalc trabalha melhor com double, por isso o cast.
        return new Dictionary<string, object>
        {
            ["OpenTickets"] = (double)openTickets,
            ["Mttr"] = (double)mttr,
            ["SlaCompliance"] = (double)slaCompliance,
            ["OpenTicketsBestMax"] = (double)context.ItsmCalcs!.OpenTicketsBestMax,
            ["OpenTicketsMediumMax"] = (double)context.ItsmCalcs.OpenTicketsMediumMax,
            ["MttrTargetHours"] = (double)context.ItsmCalcs.MttrTargetHours
        };
    }
}

public class VulnerabilityAndAttackSurfaceDomain : IDomain
{
    public DomainKey Key => DomainKey.VulnerabilityAndAttackSurface;
    public decimal Weight => DomainWeights.VulnerabilityAndAttackSurface;

    private static readonly IReadOnlyList<(IMetric Metric, decimal Weight)> Metrics =
    [
        // Mesmo padrao do dominio ITSM:
        // metricas declarativas + pesos internos + NCalc.
        (new CriticalVulnsMetric(), VulnerabilityWeights.CriticalVulns),
        (new HighVulnsMetric(), VulnerabilityWeights.HighVulns),
        (new PublicExploitMetric(), VulnerabilityWeights.PublicExploit),
        (new KevMetric(), VulnerabilityWeights.KevCatalog),
        (new InternetExposedMetric(), VulnerabilityWeights.InternetExposed),
        (new ScanCoverageMetric(), VulnerabilityWeights.ScanCoverage),
    ];

    public decimal Calculate(DomainContext context)
    {
        // Sem findings nao ha base para score de vulnerabilidade.
        if (!context.VulnFindings.Any())
        {
            return 0m;
        }

        // Preparacao dos parametros para formulas NCalc.
        var parameters = PreCalc(context);

        var weighted = Metrics.Sum(metric =>
            NCalcEvaluator.Evaluate(metric.Metric.Expression, parameters) * metric.Weight);

        // Normalizacao pelo peso efetivamente ativo.
        return weighted / VulnerabilityWeights.TotalActiveWeight;
    }

    private static Dictionary<string, object> PreCalc(DomainContext context)
    {
        // Para as metricas de risco (critical/high/exploit/kev/exposure),
        // ignoramos severidades pouco relevantes.
        var findings = context.VulnFindings
            .Where(f => f.Severity != VulnSeverity.Info && f.Severity != VulnSeverity.Unknown)
            .ToList();

        // Para scan coverage, o criterio acordado e:
        // findings com CVE / total de findings (sem filtro de severidade).
        var allFindings = context.VulnFindings.ToList();

        var meaningfulCount = findings.Count;

        var criticalCount = findings.Count(f => f.Cvss.HasValue && f.Cvss.Value > CvssRange.CriticalMin);

        var highCount = findings.Count(f =>
            f.Cvss.HasValue
                ? f.Cvss.Value >= CvssRange.HighMin && f.Cvss.Value <= CvssRange.HighMax
                : f.Severity == VulnSeverity.High);

        var hasPublicExploit = findings.Any(f => f.HasPublicExploit) ? 1 : 0;
        var hasKev = findings.Any(f => f.IsInKevCatalog) ? 1 : 0;
        var internetExposedCount = findings.Count(f => f.IsInternetExposed);
        var withCveCount = allFindings.Count(f => !string.IsNullOrWhiteSpace(f.Cve));

        var criticalRatio = meaningfulCount == 0 ? 0m : (decimal)criticalCount / meaningfulCount;
        var highRatio = meaningfulCount == 0 ? 0m : (decimal)highCount / meaningfulCount;
        var internetExposedRatio = meaningfulCount == 0 ? 0m : (decimal)internetExposedCount / meaningfulCount;
        var totalFindingsCount = allFindings.Count;
        var scanCoverageRatio = totalFindingsCount == 0 ? 0m : (decimal)withCveCount / totalFindingsCount;

        // Parametros "prontos a usar" nas expressions das metricas.
        // Tambem inclui thresholds centralizados em Common/Constants.
        return new Dictionary<string, object>
        {
            ["MeaningfulFindings"] = (double)meaningfulCount,
            ["CriticalRatio"] = (double)criticalRatio,
            ["HighRatio"] = (double)highRatio,
            ["HasPublicExploit"] = (double)hasPublicExploit,
            ["HasKev"] = (double)hasKev,
            ["InternetExposedRatio"] = (double)internetExposedRatio,
            ["InternetExposedMediumThreshold"] = (double)InternetExposedThresholds.Medium,
            ["InternetExposedHighThreshold"] = (double)InternetExposedThresholds.High,
            ["ScanCoverageRatio"] = (double)scanCoverageRatio,

            ["CriticalHighThreshold"] = (double)CriticalVulnsThresholds.High,
            ["CriticalMediumThreshold"] = (double)CriticalVulnsThresholds.Medium,
            ["HighHighThreshold"] = (double)HighVulnsThresholds.High,
            ["HighMediumThreshold"] = (double)HighVulnsThresholds.Medium,
            ["ScanCoverageHighThreshold"] = (double)ScanCoverageThresholds.High,
            ["ScanCoverageMediumThreshold"] = (double)ScanCoverageThresholds.Medium
        };
    }
}

public class ThreatLandscapeDomain : IDomain
{
    public DomainKey Key => DomainKey.ThreatLandscape;
    public decimal Weight => DomainWeights.ThreatLandscape;

    public decimal Calculate(DomainContext context) => 0m;
}

public class DetectionAndResponseDomain : IDomain
{
    public DomainKey Key => DomainKey.DetectionAndResponse;
    public decimal Weight => DomainWeights.DetectionAndResponse;

    public decimal Calculate(DomainContext context) => 0m;
}

public class IdentityAndAccessSecurityDomain : IDomain
{
    public DomainKey Key => DomainKey.IdentityAndAccessSecurity;
    public decimal Weight => DomainWeights.IdentityAndAccessSecurity;

    public decimal Calculate(DomainContext context) => 0m;
}

public class GovernanceAndResilienceDomain : IDomain
{
    public DomainKey Key => DomainKey.GovernanceAndResilience;
    public decimal Weight => DomainWeights.GovernanceAndResilience;

    public decimal Calculate(DomainContext context) => 0m;
}

public class HumanRiskDomain : IDomain
{
    public DomainKey Key => DomainKey.HumanRisk;
    public decimal Weight => DomainWeights.HumanRisk;

    public decimal Calculate(DomainContext context) => 0m;
}

public static class CompositeScoreCalculator
{
    // Calcula score final do cliente a partir dos scores de dominios disponiveis.
    // Em ambiente multi-cliente/multi-fonte, nem todos os dominios estao presentes:
    // por isso somamos apenas os que existem e normalizamos pelo peso total usado.
    public static decimal Calculate(IReadOnlyDictionary<DomainKey, decimal> domainScores)
    {
        if (domainScores.Count == 0)
        {
            return 0m;
        }

        decimal weighted = 0m;
        decimal totalWeight = 0m;

        foreach (var (key, score) in domainScores)
        {
            var weight = key switch
            {
                DomainKey.ThreatLandscape => DomainWeights.ThreatLandscape,
                DomainKey.VulnerabilityAndAttackSurface => DomainWeights.VulnerabilityAndAttackSurface,
                DomainKey.DetectionAndResponse => DomainWeights.DetectionAndResponse,
                DomainKey.IdentityAndAccessSecurity => DomainWeights.IdentityAndAccessSecurity,
                DomainKey.GovernanceAndResilience => DomainWeights.GovernanceAndResilience,
                DomainKey.OperationalSecurity => DomainWeights.OperationalSecurity,
                DomainKey.HumanRisk => DomainWeights.HumanRisk,
                _ => 0m
            };

            if (weight <= 0m)
            {
                continue;
            }

            weighted += score * weight;
            totalWeight += weight;
        }

        return totalWeight == 0m ? 0m : weighted / totalWeight;
    }
}
