namespace Silo;

/// <summary>Tenant-scoped object storage. Acts on the ambient Bedrock tenant. Objects are immutable: there is no overwrite, only new objects.</summary>
public interface ISilo
{
    /// <summary>
    /// Stores content as a new object after an inline malware scan (default for all untrusted streams).
    /// </summary>
    /// <exception cref="InfectedContentException">Malware detected — nothing is stored.</exception>
    /// <exception cref="ScanUnavailableException">The scanner failed and <see cref="SiloOptions.RejectWhenScannerFails"/> is set.</exception>
    /// <exception cref="ObjectTooLargeException"/>
    Task<SiloObject> UploadAsync(UploadRequest request, Stream content, CancellationToken cancellationToken = default);

    /// <summary>A "replace" is a new object (new id) that records what it <see cref="SiloObject.SupersedesId">supersedes</see>; the old object is untouched.</summary>
    Task<SiloObject> ReplaceAsync(Guid existingObjectId, UploadRequest request, Stream content, CancellationToken cancellationToken = default);

    /// <summary>
    /// Direct-to-provider upload, bypassing inline scanning. Allowed only when enabled, when the client attests it scanned the content,
    /// when content isn't encrypted at rest, and when the provider supports pre-signed URLs.
    /// </summary>
    /// <exception cref="DirectUploadNotAllowedException"/>
    Task<DirectUploadTicket> BeginDirectUploadAsync(DirectUploadRequest request, CancellationToken cancellationToken = default);

    /// <summary>Confirms the client finished uploading: verifies the blob exists and is within limits, records size + SHA-256, and makes the object readable.</summary>
    Task<SiloObject> CompleteDirectUploadAsync(Guid objectId, CancellationToken cancellationToken = default);

    Task<SiloObject?> GetAsync(Guid objectId, CancellationToken cancellationToken = default);

    /// <summary>Opens the content (decrypting if needed). Null when the object doesn't exist in this tenant or isn't readable (pending/quarantined).</summary>
    Task<SiloReadResult?> OpenReadAsync(Guid objectId, CancellationToken cancellationToken = default);

    /// <summary>A pre-signed download URL, or null when unsupported by the provider or the content is encrypted at rest.</summary>
    Task<Uri?> CreateDownloadUrlAsync(Guid objectId, TimeSpan lifetime, CancellationToken cancellationToken = default);

    /// <summary>Confirms ownership: marks the (type, id) tag claimed, adding it if the object wasn't tagged with it.</summary>
    Task ClaimAsync(Guid objectId, string ownerType, string ownerId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SiloObject>> FindByOwnerAsync(string ownerType, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>Readable objects older than <paramref name="olderThan"/> that nobody has claimed — candidates for cleanup.</summary>
    Task<IReadOnlyList<SiloObject>> ListUnclaimedAsync(DateTimeOffset olderThan, int take = 100, CancellationToken cancellationToken = default);

    /// <summary>Re-scans stored content; malware quarantines the object.</summary>
    Task<ScanResult> RescanAsync(Guid objectId, CancellationToken cancellationToken = default);

    /// <summary>Recomputes the SHA-256 and compares it with the recorded value.</summary>
    Task<bool> VerifyIntegrityAsync(Guid objectId, CancellationToken cancellationToken = default);

    /// <summary>Permanently deletes the object and its blob (erasure/retention). Record why in Chronicle.</summary>
    Task PurgeAsync(Guid objectId, CancellationToken cancellationToken = default);

    /// <summary>Removes direct-upload tickets never completed within <paramref name="olderThan"/>. Returns how many.</summary>
    Task<int> ExpirePendingDirectUploadsAsync(DateTimeOffset olderThan, CancellationToken cancellationToken = default);
}
