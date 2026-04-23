namespace CyberOps.Common.Constants;

// pesos  das metricas do dominio Operational Security
// estes pesos sao usados dentro do dominio nao no score composto global
public static class OperationalSecurityWeights
{
    public const decimal OpenTickets = 0.25m;
    public const decimal Mttr = 0.20m;
    public const decimal SlaCompliance = 0.10m;
    public const decimal TotalActiveWeight = OpenTickets + Mttr + SlaCompliance;
}

// referencias dos patamares de score de Open Tickets
// mantido separado para facilitar mudar sem tocar na formula principal
public static class OpenTicketsScorePercentages
{
    public const decimal Best = 1.0m;
    public const decimal Medium = 0.7m;
    public const decimal Worst = 0.3m;
}
