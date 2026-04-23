using CyberOps.Application.Scoring;
using CyberOps.Common.Constants;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;

namespace CyberOps.Tests;

public class OperationalSecurityDomainTests
{
    private static Operationalsecitsm Ticket(ItsmStatus status, decimal? hours = null, bool? breached = null)
        => new()
        {
            ClientId = 1,
            SourceSystem = SourceSystem.Jira,
            TicketKey = Guid.NewGuid().ToString(),
            IssueId = Random.Shared.Next(1, 99999),
            Status = status,
            TicketType = ItsmTicketType.Incident,
            Priority = PriorityLevel.Medium,
            Resolution = ItsmResolution.None,
            Title = "Test",
            CreatedAt = DateTime.UtcNow,
            TimeSpentHours = hours,
            FirstResponseSlaBreached = breached
        };

    [Fact]
    public void Calculate_ShouldApplyPreCalcAndExpressions_ForMixedScenario()
    {
        var tickets = new List<Operationalsecitsm>
        {
            Ticket(ItsmStatus.InProgress),
            Ticket(ItsmStatus.InProgress),
            Ticket(ItsmStatus.Closed, 8, false),
            Ticket(ItsmStatus.Closed, 12, false),
            Ticket(ItsmStatus.Closed, null, true),
            Ticket(ItsmStatus.Open)
        };

        var calcs = new ClientItsmCalcs
        {
            ClientId = 1,
            OpenTicketsBestMax = 1,
            OpenTicketsMediumMax = 3,
            MttrTargetHours = 5
        };

        var context = new DomainContext
        {
            ClientId = 1,
            ItsmTickets = tickets,
            ItsmCalcs = calcs
        };

        var domain = new OperationalSecurityDomain();
        var actual = domain.Calculate(context);

        // PreCalc esperado:
        // OpenTickets = 2 => score OpenTickets = 0.7
        // MTTR = (8 + 12)/2 = 10 => score MTTR = 5/10 = 0.5
        // SLA compliance = 2 compliant / 3 fechados com breached definido = 0.666666...
        var openTicketsScore = 0.7m;
        var mttrScore = 0.5m;
        var slaScore = 2m / 3m;

        var expected = (
            (openTicketsScore * OperationalSecurityWeights.OpenTickets) +
            (mttrScore * OperationalSecurityWeights.Mttr) +
            (slaScore * OperationalSecurityWeights.SlaCompliance)
        ) / OperationalSecurityWeights.TotalActiveWeight;

        Assert.Equal(decimal.Round(expected, 6), decimal.Round(actual, 6));
    }

    [Fact]
    public void Calculate_ShouldReturnZero_WhenNoCalcsOrNoTickets()
    {
        var domain = new OperationalSecurityDomain();

        var noCalcs = domain.Calculate(new DomainContext
        {
            ClientId = 1,
            ItsmTickets = new[] { Ticket(ItsmStatus.InProgress) }
        });

        var noTickets = domain.Calculate(new DomainContext
        {
            ClientId = 1,
            ItsmCalcs = new ClientItsmCalcs { ClientId = 1, OpenTicketsBestMax = 1, OpenTicketsMediumMax = 2, MttrTargetHours = 4 }
        });

        Assert.Equal(0m, noCalcs);
        Assert.Equal(0m, noTickets);
    }

    [Fact]
    public void NCalcEvaluator_ShouldEvaluateOpenTicketsExpression()
    {
        var expr = new OpenTicketsMetric().Expression;
        var value = NCalcEvaluator.Evaluate(expr, new Dictionary<string, object>
        {
            ["OpenTickets"] = 2d,
            ["OpenTicketsBestMax"] = 1d,
            ["OpenTicketsMediumMax"] = 3d
        });

        Assert.Equal(0.7m, value);
    }
}
