using CyberOps.Application.Scoring;
using CyberOps.Domain.Enums;

namespace CyberOps.Tests;

public class CompositeScoreTests
{
    [Fact]
    public void Calculate_ShouldNormalizeByProvidedDomainWeights()
    {
        var scores = new Dictionary<DomainKey, decimal>
        {
            [DomainKey.OperationalSecurity] = 0.8m,
            [DomainKey.VulnerabilityAndAttackSurface] = 0.6m
        };

        var actual = CompositeScoreCalculator.Calculate(scores);

        var expected = (
            (0.8m * DomainWeights.OperationalSecurity) +
            (0.6m * DomainWeights.VulnerabilityAndAttackSurface)
        ) / (DomainWeights.OperationalSecurity + DomainWeights.VulnerabilityAndAttackSurface);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Calculate_ShouldReturnZero_WhenNoDomainScores()
    {
        var actual = CompositeScoreCalculator.Calculate(new Dictionary<DomainKey, decimal>());
        Assert.Equal(0m, actual);
    }
}
