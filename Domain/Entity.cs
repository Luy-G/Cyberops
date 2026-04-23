using CyberOps.Domain.Enums;

namespace CyberOps.Domain.Entities;



// Entity normalizada para tickets ITSM.
// preenchida no mapeamento de ingestao ItsmMap.cs
// usada nos calculos do dominio Operational Security.
public class Operationalsecitsm
{
    public long ItsmTicketId { get; set; }
    public long ClientId { get; set; }
    public SourceSystem SourceSystem { get; set; }
    public required string TicketKey { get; set; }
    public long IssueId { get; set; }
    public ItsmStatus Status { get; set; }
    public ItsmTicketType TicketType { get; set; }
    public PriorityLevel Priority { get; set; }
    public ItsmResolution Resolution { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    public string? DescriptionHtml { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public string? CreatorName { get; set; }
    public string? CreatorEmail { get; set; }
    public string? CurrentAssigneeName { get; set; }
    public string? CurrentAssigneeEmail { get; set; }
    public string? ReporterName { get; set; }
    public string? ReporterEmail { get; set; }
    public string? FirstResponseDurationText { get; set; }
    public long? FirstResponseDurationMs { get; set; }
    public DateTime? FirstResponseSlaStartAt { get; set; }
    public DateTime? FirstResponseSlaCompleteAt { get; set; }
    public bool? FirstResponseSlaBreached { get; set; }
    public decimal? TimeSpentHours { get; set; }
    public DateTime IngestedAt { get; set; } = DateTime.UtcNow;
}

//thresholds ITSM por cliente.
//permite comportamento diferente por cliente 
public class ClientItsmCalcs
{
    public long ClientItsmCalculationId { get; set; }
    public long ClientId { get; set; }
    public int OpenTicketsBestMax { get; set; }
    public int OpenTicketsMediumMax { get; set; }
    public decimal MttrTargetHours { get; set; }
}

// Entity normalizada para findings de vulnerabilidade
// preenchida pela ingestao de Vulnerability e usada no dominio VulnerabilityAndAttackSurface
public class VulnerabilityAttackSurface
{
    public long VulnerabilityFindingId { get; set; }
    public long ClientId { get; set; }
    public SourceSystem SourceSystem { get; set; }
    public ScanEngine ScanEngine { get; set; }
    public required string FindingKey { get; set; }
    public VulnSeverity Severity { get; set; }
    public required string Title { get; set; }
    public string? Cve { get; set; }
    public decimal? Cvss { get; set; }
    public string? Host { get; set; }
    public string? Port { get; set; }
    public string? Evidence { get; set; }
    public string? Description { get; set; }
    public string? Impact { get; set; }
    public string? Recommendation { get; set; }
    public bool HasPublicExploit { get; set; }
    public bool IsInternetExposed { get; set; }
    public bool IsInKevCatalog { get; set; }
    public DateTime IngestedAt { get; set; } = DateTime.UtcNow;
}

// configuracao por cliente para dominio de vulnerabilidade
// deixa o contrato preparado para crescer
public class ClientVulnCalcs
{
    public long ClientVulnCalculationId { get; set; }
    public long ClientId { get; set; }
}

// contrato default para metricas declarativas.
// cada metrica tem uma expression para separar formula de codigo
public interface IMetric
{
    int Id { get; set; }
    string Name { get; set; }
    string Description { get; set; }
    string Expression { get; set; }
}

public class OpenTicketsMetric : IMetric
{
    public int Id { get; set; } = 1;
    public string Name { get; set; } = "Open Tickets Score";
    public string Description { get; set; } = "Score based on in-progress tickets.";
    // usada no Domains.cs no OperationalSecurityDomain.
    // 1.0 = melhor caso, 0.7 = medio, 0.3 = pior.
    public string Expression { get; set; } =
        "if(OpenTickets <= OpenTicketsBestMax, 1.0, if(OpenTickets <= OpenTicketsMediumMax, 0.7, 0.3))";
}

public class MttrMetric : IMetric
{
    public int Id { get; set; } = 2;
    public string Name { get; set; } = "MTTR Score";
    public string Description { get; set; } = "Score based on MTTR against target.";
    // compara MTTR real com target do cliente
    // Se MTTR for maior que target score degrada proporcionalmente
    public string Expression { get; set; } =
        "if(MttrTargetHours <= 0, 0, if(Mttr <= MttrTargetHours, 1, MttrTargetHours / Mttr))";
}

public class SlaComplianceMetric : IMetric
{
    public int Id { get; set; } = 3;
    public string Name { get; set; } = "SLA Compliance Score";
    public string Description { get; set; } = "Closed tickets without SLA breach ratio.";
    // valor ja calculado no PreCalc()
    public string Expression { get; set; } = "SlaCompliance";
}


public class CriticalVulnsMetric : IMetric
{
    public int Id { get; set; } = 101;
    public string Name { get; set; } = "Critical Vulnerabilities Score";
    public string Description { get; set; } = "Score based on critical vulnerabilities ratio.";
    // score por ratio de criticos
    // thresholds vem de VulnConstants.cs
    public string Expression { get; set; } =
        "if(MeaningfulFindings <= 0, 0, if(CriticalRatio > CriticalHighThreshold, 1.0, if(CriticalRatio >= CriticalMediumThreshold, 0.5, if(CriticalRatio > 0, 0.25, 0))))";
}

public class HighVulnsMetric : IMetric
{
    public int Id { get; set; } = 102;
    public string Name { get; set; } = "High Vulnerabilities Score";
    public string Description { get; set; } = "Score based on high vulnerabilities ratio.";
    // mesma logica da metrica de criticos mas para severidade High
    public string Expression { get; set; } =
        "if(MeaningfulFindings <= 0, 0, if(HighRatio > HighHighThreshold, 1.0, if(HighRatio >= HighMediumThreshold, 0.5, if(HighRatio > 0, 0.25, 0))))";
}

public class PublicExploitMetric : IMetric
{
    public int Id { get; set; } = 103;
    public string Name { get; set; } = "Public Exploit Score";
    public string Description { get; set; } = "Binary score when public exploit exists.";
    // Binario pois existe exploit publico = risco alto na metrica
    public string Expression { get; set; } = "if(HasPublicExploit > 0, 1.0, 0)";
}

public class KevMetric : IMetric
{
    public int Id { get; set; } = 104;
    public string Name { get; set; } = "KEV Score";
    public string Description { get; set; } = "Binary score when finding exists in KEV catalog.";
    // Binario pq finding em KEV catalog (CISA) aumenta logo o risco
    public string Expression { get; set; } = "if(HasKev > 0, 1.0, 0)";
}

public class InternetExposedMetric : IMetric
{
    public int Id { get; set; } = 105;
    public string Name { get; set; } = "Internet Exposed Score";
    public string Description { get; set; } = "Score based on internet-exposed findings ratio.";
    // score por ratio de exposicao internet
    public string Expression { get; set; } =
        "if(InternetExposedRatio == 0, 0, if(InternetExposedRatio < InternetExposedMediumThreshold, 0.1, if(InternetExposedRatio <= InternetExposedHighThreshold, 0.5, 0.8)))";
}

public class ScanCoverageMetric : IMetric
{
    public int Id { get; set; } = 106;
    public string Name { get; set; } = "Scan Coverage Score";
    public string Description { get; set; } = "Risk score based on CVE coverage quality.";
    // score alto significa pior cobertura de dados de CVE
    // quanto maior a cobertura, menor o risco desta metrica
    public string Expression { get; set; } =
        "if(MeaningfulFindings <= 0, 0, if(ScanCoverageRatio >= ScanCoverageHighThreshold, 0, if(ScanCoverageRatio >= ScanCoverageMediumThreshold, 0.25, if(ScanCoverageRatio > 0, 0.5, 1.0))))";
}
