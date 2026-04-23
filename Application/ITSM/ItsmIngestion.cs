using System.Text.Json;
using CyberOps.Application.Ingestion;
using CyberOps.Domain.Entities;

namespace CyberOps.Application.ITSM;

// Ingestao ITSM:
// JSON bruto -> DTO -> validacao -> entidade interna Operationalsecitsm.
public class SogilubItsmIngestion
{
    // Metodo sincrono porque aqui nao ha chamadas externas.
    public IngestionResult<Operationalsecitsm> Ingest(string json, long clientId)
    {
        // Mantem processamento parcial: erros por linha nao bloqueiam tudo.
        var errors = new List<string>();
        var items = new List<Operationalsecitsm>();

        List<SogilubItsmDto>? dtos;
        try
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                // Formato 1: array direto de tickets.
                dtos = JsonSerializer.Deserialize<List<SogilubItsmDto>>(json, options);
            }
            else
            {
                // Formato 2: resposta OData com tickets em "value".
                var odataResponse = JsonSerializer.Deserialize<SogilubItsmODataResponseDto>(json, options);
                dtos = odataResponse?.Value;
            }
        }
        catch (Exception ex)
        {
            // JSON invalido estruturalmente.
            return new IngestionResult<Operationalsecitsm>
            {
                Errors = [$"Invalid ITSM JSON: {ex.Message}"]
            };
        }

        // JSON vazio/nao compativel com o DTO esperado.
        if (dtos is null)
        {
            return new IngestionResult<Operationalsecitsm>
            {
                Errors = ["ITSM JSON is empty or invalid."]
            };
        }

        for (var i = 0; i < dtos.Count; i++)
        {
            var dto = dtos[i];
            // Valida obrigatorios e coerencia basica antes do map.
            var validationErrors = SogilubItsmValidator.Validate(dto);
            if (validationErrors.Count > 0)
            {
                // Index da linha ajuda a localizar o problema no ficheiro de origem.
                errors.AddRange(validationErrors.Select(e => $"ITSM row {i + 1}: {e}"));
                continue;
            }

            // Converte para entidade normalizada usada no scoring.
            items.Add(SogilubItsmMapper.Map(dto, clientId));
        }

        // Entrega final com itens validos + lista de erros nao fatais.
        return new IngestionResult<Operationalsecitsm>
        {
            Items = items,
            Errors = errors
        };
    }
}
