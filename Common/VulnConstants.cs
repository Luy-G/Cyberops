namespace CyberOps.Common.Constants;

// pesos  do dominio de Vulnerability & Attack Surface
// Alguns tao so como placeholders para futuro
public static class VulnerabilityWeights
{
    public const decimal CriticalVulns   = 0.25m;
    public const decimal HighVulns       = 0.15m;
    public const decimal PublicExploit   = 0.15m;
    public const decimal KevCatalog      = 0.15m;
    public const decimal InternetExposed = 0.10m;
    public const decimal MeanTimeToPatch = 0.05m;
    public const decimal ScanCoverage    = 0.05m;
    public const decimal AssetsExposed   = 0.10m;

    // por agora Critical, High, PublicExploit, KEV, InternetExposed, ScanCoverage
    public const decimal TotalActiveWeight =
        CriticalVulns + HighVulns + PublicExploit + KevCatalog + InternetExposed + ScanCoverage;
}

// thresholds para classificar ratio de critical findings
public static class CriticalVulnsThresholds
{
    public const decimal High   = 0.05m;
    public const decimal Medium = 0.03m;
}

// thresholds para classificar ratio de high findings
public static class HighVulnsThresholds
{
    public const decimal High   = 0.10m;
    public const decimal Medium = 0.05m;
}

// limiares do ratio de exposicao internet
public static class InternetExposedThresholds
{
    public const decimal Medium = 0.33m;
    public const decimal High = 0.66m;
}

// degraus de score usados na expression de internet exposure
public static class InternetExposedScoreSteps
{
    public const decimal None = 0.0m;
    public const decimal Low = 0.1m;
    public const decimal Medium = 0.5m;
    public const decimal High = 0.8m;
}

// faixas de CVSS usadas no PreCalc para classificar critical/high
public static class CvssRange
{
    public const decimal CriticalMin = 9.0m;
    public const decimal HighMin     = 7.0m;
    public const decimal HighMax     = 8.9m;
}

// escala padrao de score para metricas por ratio
public static class VulnRatioScoreSteps
{
    public const decimal High   = 1.00m;
    public const decimal Medium = 0.50m;
    public const decimal Low    = 0.25m;
    public const decimal None   = 0.00m;
}

// cobertura de scan (proporcao de findings com CVE preenchido)
public static class ScanCoverageThresholds
{
    public const decimal High   = 0.80m;
    public const decimal Medium = 0.50m;
}
