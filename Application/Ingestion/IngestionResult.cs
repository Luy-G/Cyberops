namespace CyberOps.Application.Ingestion;

// Envelope generico para ingestao de qualquer fonte.
// Items = registos validos convertidos para entidades internas.
// Errors = problemas por linha/registo (nao bloqueia tudo).
public class IngestionResult<T>
{
    public IReadOnlyList<T> Items { get; init; } = [];
    public IReadOnlyList<string> Errors { get; init; } = [];
    public bool Success => Errors.Count == 0;
}
