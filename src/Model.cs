namespace Silo;

public enum SiloObjectStatus
{
    /// <summary>A direct-upload ticket was issued but the client hasn't completed it.</summary>
    PendingDirectUpload,
    /// <summary>Scanned clean (inline by Silo, or attested by the client for direct uploads) and readable.</summary>
    Clean,
    /// <summary>A later scan found malware. Kept for forensics, never readable.</summary>
    Quarantined,
}

/// <summary>An owner tag (e.g. <c>("invoice","inv-42")</c>). Tags are passive hints until claimed.</summary>
public sealed record OwnerRef(string Type, string Id);

public sealed record SiloOwner(string Type, string Id, bool Claimed, DateTimeOffset? ClaimedAt);

/// <summary>Immutable object metadata. A "replace" is always a new object (see <see cref="SupersedesId"/>).</summary>
public sealed record SiloObject(
    Guid Id,
    string TenantId,
    string FileName,
    string ContentType,
    long Length,
    string Sha256,
    SiloObjectStatus Status,
    string ScanSource,
    DateTimeOffset? ScannedAt,
    bool Encrypted,
    Guid? SupersedesId,
    DateTimeOffset CreatedAt,
    string? CreatedBy,
    IReadOnlyList<SiloOwner> Owners);

public sealed class UploadRequest
{
    public required string FileName { get; init; }
    public string? ContentType { get; init; }
    public string? CreatedBy { get; init; }
    /// <summary>Passive owner tags. Not validated or enforced at write time; confirm them later with <see cref="ISilo.ClaimAsync"/>.</summary>
    public IReadOnlyList<OwnerRef>? OwnerTags { get; init; }
    /// <summary>Set by <see cref="ISilo.ReplaceAsync"/>.</summary>
    public Guid? SupersedesId { get; init; }
}

/// <summary>The client's statement that it scanned the content itself. Required for direct-to-provider uploads.</summary>
public sealed record ClientScanAttestation(string Scanner, string? Version, DateTimeOffset ScannedAt);

public sealed class DirectUploadRequest
{
    public required string FileName { get; init; }
    public string? ContentType { get; init; }
    public string? CreatedBy { get; init; }
    public IReadOnlyList<OwnerRef>? OwnerTags { get; init; }
    public ClientScanAttestation? ClientScan { get; init; }
    public TimeSpan? UrlLifetime { get; init; }
}

/// <summary>Where the client uploads to (a provider pre-signed URL), then calls <see cref="ISilo.CompleteDirectUploadAsync"/>.</summary>
public sealed record DirectUploadTicket(Guid ObjectId, Uri UploadUrl, DateTimeOffset ExpiresAt);

public sealed class SiloReadResult(SiloObject metadata, Stream content) : IAsyncDisposable, IDisposable
{
    public SiloObject Metadata { get; } = metadata;
    public Stream Content { get; } = content;
    public void Dispose() => Content.Dispose();
    public ValueTask DisposeAsync() => Content.DisposeAsync();
}

public class SiloException(string message) : Exception(message);
public sealed class ObjectNotFoundException(Guid id) : SiloException($"Object {id} was not found.");
public sealed class ObjectTooLargeException(long max) : SiloException($"Object exceeds the maximum size of {max} bytes.");
public sealed class InfectedContentException(string signature) : SiloException($"Upload rejected: malware detected ({signature}).") { public string Signature { get; } = signature; }
public sealed class ScanUnavailableException(string message, Exception? inner = null) : SiloException(message) { public Exception? Cause { get; } = inner; }
public sealed class DirectUploadNotAllowedException(string message) : SiloException(message);
public sealed class BlobAlreadyExistsException(string key) : SiloException($"Blob '{key}' already exists; stored objects are immutable.");
public sealed class BlobNotFoundException(string key) : SiloException($"Blob '{key}' does not exist.");
