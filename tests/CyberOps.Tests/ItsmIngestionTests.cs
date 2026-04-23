using CyberOps.Application.ITSM;
using CyberOps.Domain.Enums;

namespace CyberOps.Tests;

public class ItsmIngestionTests
{
    [Fact]
    public void Ingest_ShouldParseODataValueWrapper_AndMapFields()
    {
        const string json = """
        {
          "value": [
            {
              "Key": "SR-1001",
              "Issue ID": 1001.0,
              "Current Status": "Closed",
              "Issue Type": "Sub-task",
              "Priority": "P2 (Urgent)",
              "Resolution": "Done",
              "Summary": "Ticket test",
              "Description": "desc",
              "Description (HTML)": "<p>desc</p>",
              "Created": "2026-03-10T09:38:45.271Z",
              "Updated": "2026-03-11T08:50:54.206Z",
              "Resolved": "2026-03-11T09:00:00.000Z",
              "Creator:  Name": "Rodrigo Alves",
              "Creator:  Email": "rodrigo@example.com",
              "Current Assignee:  Name": "Technology - Support",
              "Current Assignee:  Email": "support@example.com",
              "Reporter:  Name": "Reporter",
              "Reporter:  Email": "reporter@example.com",
              "Time to first response": "57m",
              "Time to first response: SLA Start date": "2026-03-10T09:38:45.271Z",
              "Time to first response: SLA Complete date": "2026-03-10T09:41:29.645Z",
              "Time Spent": 2.5,
              "Time to first response: Breached?": "true"
            }
          ]
        }
        """;

        var ingestion = new SogilubItsmIngestion();
        var result = ingestion.Ingest(json, clientId: 42);

        Assert.Empty(result.Errors);
        var item = Assert.Single(result.Items);

        Assert.Equal(42, item.ClientId);
        Assert.Equal("SR-1001", item.TicketKey);
        Assert.Equal(1001L, item.IssueId);
        Assert.Equal(ItsmStatus.Closed, item.Status);
        Assert.Equal(ItsmTicketType.Subtask, item.TicketType);
        Assert.Equal(PriorityLevel.High, item.Priority);
        Assert.Equal(ItsmResolution.Done, item.Resolution);
        Assert.Equal("Rodrigo Alves", item.CreatorName);
        Assert.Equal(2.5m, item.TimeSpentHours);
        Assert.True(item.FirstResponseSlaBreached);
    }

    [Fact]
    public void Ingest_ShouldParseArrayRoot()
    {
        const string json = """
        [
          {
            "Key": "SR-2001",
            "Issue ID": 2001,
            "Current Status": "In Progress",
            "Summary": "Array root",
            "Created": "2026-03-10T09:38:45.271Z"
          }
        ]
        """;

        var ingestion = new SogilubItsmIngestion();
        var result = ingestion.Ingest(json, clientId: 1);

        Assert.Empty(result.Errors);
        var item = Assert.Single(result.Items);
        Assert.Equal("SR-2001", item.TicketKey);
        Assert.Equal(ItsmStatus.InProgress, item.Status);
        Assert.Equal(ItsmTicketType.Unknown, item.TicketType);
        Assert.Equal(PriorityLevel.Unknown, item.Priority);
    }

    [Fact]
    public void Ingest_ShouldReturnValidationError_WhenCreatedMissing()
    {
        const string json = """
        [
          {
            "Key": "SR-3001",
            "Issue ID": 3001,
            "Current Status": "Closed",
            "Summary": "Missing created"
          }
        ]
        """;

        var ingestion = new SogilubItsmIngestion();
        var result = ingestion.Ingest(json, clientId: 1);

        Assert.Empty(result.Items);
        Assert.Contains(result.Errors, e => e.Contains("Created date is required."));
    }

    [Fact]
    public void Ingest_ShouldReturnError_WhenJsonInvalid()
    {
        const string json = "this is not json";

        var ingestion = new SogilubItsmIngestion();
        var result = ingestion.Ingest(json, clientId: 1);

        Assert.Empty(result.Items);
        Assert.Contains(result.Errors, e => e.StartsWith("Invalid ITSM JSON:"));
    }

    [Fact]
    public void Ingest_ShouldReturnValidationError_WhenTimeSpentNegative()
    {
        const string json = """
        [
          {
            "Key": "SR-4001",
            "Issue ID": 4001,
            "Current Status": "Closed",
            "Summary": "Negative time",
            "Created": "2026-03-10T09:38:45.271Z",
            "Time Spent": -1
          }
        ]
        """;

        var ingestion = new SogilubItsmIngestion();
        var result = ingestion.Ingest(json, clientId: 1);

        Assert.Empty(result.Items);
        Assert.Contains(result.Errors, e => e.Contains("Time spent cannot be negative."));
    }
}
