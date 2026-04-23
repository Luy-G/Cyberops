namespace CyberOps.Domain.Enums;

// Estado de ticket ITSM apos normalizacao.
// Usado em filtros de calculo (ex: InProgress para open tickets, Closed para MTTR/SLA).
public enum ItsmStatus
{
    Unknown = 0,
    New = 1,
    Open = 2,
    Triaged = 3,
    InProgress = 4,
    Pending = 5,
    OnHold = 6,
    Resolved = 7,
    Closed = 8,
    Cancelled = 9,
    Reopened = 10
}

// Tipo funcional do ticket ITSM.
public enum ItsmTicketType
{
    Unknown = 0,
    Incident = 1,
    Task = 2,
    Subtask = 3,
    ServiceRequest = 4,
    Problem = 5,
    Change = 6,
    Case = 7,
    Other = 8
}

// Prioridade normalizada.
public enum PriorityLevel
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

// Resultado/resolucao final normalizada.
public enum ItsmResolution
{
    None = 0,
    Unknown = 1,
    Done = 2,
    Resolved = 3,
    Fixed = 4,
    Workaround = 5,
    Duplicate = 6,
    WontFix = 7,
    NotReproducible = 8,
    Cancelled = 9,
    Rejected = 10
}

// Chaves dos dominios funcionais do modelo da dashboard.
// Usado para mapear score de dominio e peso global.
public enum DomainKey
{
    Unknown = 0,
    OperationalSecurity = 1,
    ThreatLandscape = 2,
    DetectionAndResponse = 3,
    HumanRisk = 4,
    VulnerabilityAndAttackSurface = 5,
    IdentityAndAccessSecurity = 6,
    GovernanceAndResilience = 7
}

// Origem dos dados apos ingestao.
public enum SourceSystem
{
    Jira = 1,
    Other = 2
}

// Ferramenta de scan de vulnerabilidade.
public enum ScanEngine
{
    Unknown = 0,
    Nmap = 1,
    Nessus = 2,
    Qualys = 3,
    Rapid7 = 4,
    OpenVas = 5,
    CheckPoint = 6
}

// Severidade normalizada de vulnerabilidade.
public enum VulnSeverity
{
    Unknown = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}
