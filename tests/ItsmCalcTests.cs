using CyberOps.Application.Scoring;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;
using Xunit;

namespace CyberOps.Tests;

// Estes testes servem como exemplos vivos da logica de calculo ITSM.
// Mesmo sem conhecer C#, cada teste descreve um cenario e o resultado esperado.
public class ItsmCalculationsTests
{
    // Helper para criar tickets de teste com defaults simples.
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
    public void CalculateOpenTicketsScore_ShouldReturnBest_WhenBelowBestMaxThreshold()
    {
        // 1 ticket em progresso, threshold best=10 => score maximo.
        var tickets = new[] { Ticket(ItsmStatus.InProgress) };
        var calcs = new ClientItsmCalcs { ClientId = 1, OpenTicketsBestMax = 10, OpenTicketsMediumMax = 50, MttrTargetHours = 24 };
        var score = ItsmCalculations.CalculateOpenTicketsScore(tickets, calcs);
        Assert.Equal(1.0m, score);
    }
    [Fact]
    public void CalculateMttrScore_ShouldReturnHalf_WhenMttrIsDoubleTarget()
    {
        // MTTR medio = (8+12)/2 = 10h; target=5h => score = 5/10 = 0.5.
        var tickets = new[] { Ticket(ItsmStatus.Closed, 8), Ticket(ItsmStatus.Closed, 12) };
        var calcs = new ClientItsmCalcs { ClientId = 1, OpenTicketsBestMax = 10, OpenTicketsMediumMax = 50, MttrTargetHours = 5 };
        var score = ItsmCalculations.CalculateMttrScore(tickets, calcs);
        Assert.Equal(0.5m, score);
    }

    [Fact]
    public void CalculateSlaCompliance_ShouldReturnThreeQuarters_WhenThreeOfFourComply()
    {
        // 3 de 4 tickets fechados sem breach => 3/4 = 0.75.
        var tickets = new[]
        {
            Ticket(ItsmStatus.Closed, breached: false),
            Ticket(ItsmStatus.Closed, breached: false),
            Ticket(ItsmStatus.Closed, breached: false),
            Ticket(ItsmStatus.Closed, breached: true)
        };

        var score = ItsmCalculations.CalculateSlaCompliance(tickets);
        Assert.Equal(0.75m, score);
    }
}
