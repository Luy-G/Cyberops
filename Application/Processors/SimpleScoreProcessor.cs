using CyberOps.Application.Contracts.Processing;
using CyberOps.Application.ITSM;
using CyberOps.Application.Scoring;
using CyberOps.Application.Vuln;
using CyberOps.Domain.Entities;
using CyberOps.Domain.Enums;

namespace CyberOps.Application.Processors;

// coordenar ingestao -> construir contexto -> calcular dominios -> score composto
public class SimpleScoreProcessor : IProcessor
{
    // transformar JSON bruto em entidades internas normalizadas
    private readonly SogilubItsmIngestion _itsmIngestion;
    private readonly SogilubVulnIngestion _vulnIngestion;

    // injecao de dependencias para manter o processor simples e testavel
    public SimpleScoreProcessor(SogilubItsmIngestion itsmIngestion, SogilubVulnIngestion vulnIngestion)
    {
        _itsmIngestion = itsmIngestion;
        _vulnIngestion = vulnIngestion;
    }

    // metodo central chamado pela camada de aplicacao/API
    // recebe input por cliente e devolve resultado pronto para consumo
    public async Task<ProcessorResult> ProcessAsync(ProcessorInput input)
    {
        // erros acumulados de todas as fontes
        var errors = new List<string>();
        // colecoes normalizadas usadas nos calculos
        var tickets = new List<Operationalsecitsm>();
        var findings = new List<VulnerabilityAttackSurface>();

        // ITSM e opcional-> so ingere se vier payload
        if (!string.IsNullOrWhiteSpace(input.ItsmJson))
        {
            var result = _itsmIngestion.Ingest(input.ItsmJson, input.ClientId);
            errors.AddRange(result.Errors);
            tickets.AddRange(result.Items);
        }

        // Vulnerability e opcional e assincro (pode incluir chamada a KEV catalog)
        if (!string.IsNullOrWhiteSpace(input.VulnJson))
        {
            var result = await _vulnIngestion.IngestAsync(input.VulnJson, input.ClientId);
            errors.AddRange(result.Errors);
            findings.AddRange(result.Items);
        }

        // contexto unico para todos os dominios
        // concentra dados de entrada + configuracao de calculo por cliente
        var context = new DomainContext
        {
            ClientId = input.ClientId,
            ItsmTickets = tickets,
            VulnFindings = findings,
            ItsmCalcs = input.ItsmCalcs,
            VulnCalcs = input.VulnCalcs
        };

        // se o chamador nao indicar dominios, usa os 2 que hoje estao ativos.
        // Isto suporta cobertura parcial sem obrigar todos os 7 dominios.
        var activeDomains = input.ActiveDomains.Count > 0
            ? input.ActiveDomains
            : new IDomain[] { new OperationalSecurityDomain(), new VulnerabilityAndAttackSurfaceDomain() };

        // Calcula score de cada dominio de forma independente.
        var domainScores = new Dictionary<DomainKey, decimal>();
        foreach (var domain in activeDomains)
            domainScores[domain.Key] = domain.Calculate(context);

        // Calcula score final composto com normalizacao por pesos.
        var composite = CompositeScoreCalculator.Calculate(domainScores);

        // Resultado final do processamento.
        return new ProcessorResult
        {
            Success = errors.Count == 0,
            Errors = errors,
            ItsmTickets = tickets,
            VulnFindings = findings,
            DomainScores = domainScores,
            CompositeScore = composite
        };
    }
}
