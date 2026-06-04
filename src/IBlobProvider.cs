namespace Silo;

/// <summary>A storage backend. Providers only see opaque keys (<c>{tenant}/{objectId}</c>) — never file names or metadata.</summary>
public interface IBlobProvider
{
    string Name { get; }

    /// <summary>Writes a NEW blob. Throws <see cref="BlobAlreadyExistsException"/> if the key exists — stored objects are immutable.</summary>
    Task PutAsync(string key, Stream content, string? contentType, CancellationToken ct = default);

    /// <exception cref="BlobNotFoundException"/>
    Task<Stream> OpenReadAsync(string key, CancellationToken ct = default);

    Task<long?> GetLengthAsync(string key, CancellationToken ct = default);

    /// <summary>Removes a blob (purge/cleanup only; there is no overwrite).</summary>
    Task DeleteAsync(string key, CancellationToken ct = default);

    /// <summary>A pre-signed URL a client can PUT to, or null if the provider can't do direct uploads.</summary>
    Task<Uri?> CreateUploadUrlAsync(string key, TimeSpan lifetime, string? contentType, CancellationToken ct = default);

    /// <summary>A pre-signed URL a client can GET from, or null if unsupported.</summary>
    Task<Uri?> CreateDownloadUrlAsync(string key, TimeSpan lifetime, CancellationToken ct = default);
}

internal static class BlobKeys
{
    /// <summary>Validates a provider key: 2-3 segments of [A-Za-z0-9._-], no traversal.</summary>
    public static string Validate(string key)
    {
        var parts = key.Split('/');
        if (parts.Length is < 1 or > 4 || parts.Any(p => p.Length == 0 || p is "." or ".." || !p.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
            throw new ArgumentException($"Invalid blob key '{key}'.", nameof(key));
        return key;
    }
}
