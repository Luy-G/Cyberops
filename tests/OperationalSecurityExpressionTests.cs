using CyberOps.Application.Scoring;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;
using Xunit;

namespace CyberOps.Tests;

// Testes focados em formulas NCalc do dominio Operational Security.
// Aqui validamos "a matematica da expression" com cenarios simples e controlados.
public class OperationalSecurityExpressionTests
{
    // Helper para criar tickets de teste com defaults.
    // Facilita montar cenarios sem repetir codigo.
    private static Operationalsecitsm Ticket(ItsmStatus status, decimal? timeSpentHours = null, bool? firstResponseSlaBreached = null)
    {
        return new Operationalsecitsm
        {
            ClientId = 1,
            SourceSystem = SourceSystem.Jira,
            TicketKey = Guid.NewGuid().ToString(),
            IssueId = Random.Shared.Next(1, 100000),
            Status = status,
            TicketType = ItsmTicketType.Incident,
            Priority = PriorityLevel.Medium,
            Resolution = ItsmResolution.None,
            Title = "Test ticket",
            CreatedAt = DateTime.UtcNow,
            TimeSpentHours = timeSpentHours,
            FirstResponseSlaBreached = firstResponseSlaBreached
        };
    }

    // Helper de avaliacao:
    // recebe expression da metrica + tickets e executa via NCalcEvaluator.
    // Os thresholds usados nas expressions sao passados aqui.
    private static decimal Eval(string expression, IReadOnlyList<Operationalsecitsm> tickets, int bestMax = 2, int mediumMax = 5, decimal mttrTargetHours = 6)
    {
        var parameters = new Dictionary<string, object>
        {
            ["OpenTicketsBestMax"] = bestMax,
            ["OpenTicketsMediumMax"] = mediumMax,
            ["MttrTargetHours"] = mttrTargetHours
        };

        return NCalcEvaluator.Evaluate(expression, parameters, tickets);
    }

    [Fact]
    public void OpenTicketsExpression_ShouldReturn_1_0_WhenWithinBestRange()
    {
        // 1 ticket em progresso com bestMax=2 => score maximo 1.0.
        var tickets = new[] { Ticket(ItsmStatus.InProgress), Ticket(ItsmStatus.Closed) };
        var result = Eval(new OpenTicketsMetric().Expression, tickets, bestMax: 2, mediumMax: 5);
        Assert.Equal(1.0m, result);
    }
    [Fact]
    public void MttrExpression_ShouldReturn_0_5_WhenAverageIsDoubleTarget()
    {
        // MTTR medio = 10h; target=5h => formula devolve 5/10 = 0.5.
        var tickets = new[] { Ticket(ItsmStatus.Closed, 8), Ticket(ItsmStatus.Closed, 12) };
        var result = Eval(new MttrMetric().Expression, tickets, mttrTargetHours: 5);
        Assert.Equal(0.5m, result);
    }

    [Fact]
    public void SlaExpression_ShouldReturn_0_75_WhenThreeOfFourAreCompliant()
    {
        // 3 fechados sem breach em 4 fechados totais => 0.75.
        var tickets = new[]
        {
            Ticket(ItsmStatus.Closed, firstResponseSlaBreached: false),
            Ticket(ItsmStatus.Closed, firstResponseSlaBreached: false),
            Ticket(ItsmStatus.Closed, firstResponseSlaBreached: false),
            Ticket(ItsmStatus.Closed, firstResponseSlaBreached: true)
        };

        var result = Eval(new SlaComplianceMetric().Expression, tickets);
        Assert.Equal(0.75m, result);
    }
}
