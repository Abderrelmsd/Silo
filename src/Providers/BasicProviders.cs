using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;

namespace Silo.Providers;

/// <summary>Volatile provider for tests/dev. Supports fake upload URLs when <see cref="UploadUrlBase"/> is set.</summary>
public sealed class InMemoryBlobProvider : IBlobProvider
{
    private readonly ConcurrentDictionary<string, byte[]> _blobs = new();
    public string Name => "memory";
    public Uri? UploadUrlBase { get; set; }
    public IReadOnlyCollection<string> Keys => [.. _blobs.Keys];
    public byte[]? Raw(string key) => _blobs.GetValueOrDefault(key);

    public async Task PutAsync(string key, Stream content, string? contentType, CancellationToken ct = default)
    {
        BlobKeys.Validate(key);
        using var ms = new MemoryStream();
        await content.CopyToAsync(ms, ct);
        if (!_blobs.TryAdd(key, ms.ToArray())) throw new BlobAlreadyExistsException(key);
    }

    /// <summary>Simulates a client uploading via the pre-signed URL.</summary>
    public void SimulateDirectUpload(string key, byte[] bytes) => _blobs[key] = bytes;

    public Task<Stream> OpenReadAsync(string key, CancellationToken ct = default)
        => _blobs.TryGetValue(BlobKeys.Validate(key), out var b) ? Task.FromResult<Stream>(new MemoryStream(b, writable: false)) : throw new BlobNotFoundException(key);

    public Task<long?> GetLengthAsync(string key, CancellationToken ct = default) => Task.FromResult<long?>(_blobs.TryGetValue(key, out var b) ? b.Length : null);
    public Task DeleteAsync(string key, CancellationToken ct = default) { _blobs.TryRemove(key, out _); return Task.CompletedTask; }
    public Task<Uri?> CreateUploadUrlAsync(string key, TimeSpan lifetime, string? contentType, CancellationToken ct = default) => Task.FromResult(UploadUrlBase is null ? null : new Uri(UploadUrlBase, key));
    public Task<Uri?> CreateDownloadUrlAsync(string key, TimeSpan lifetime, CancellationToken ct = default) => Task.FromResult(UploadUrlBase is null ? null : new Uri(UploadUrlBase, key + "?dl"));
}

/// <summary>Stores blobs as files under a root directory (<c>root/{tenant}/{id}</c>). No pre-signed URLs.</summary>
public sealed class LocalFileSystemBlobProvider(string rootPath) : IBlobProvider
{
    private readonly string _root = Path.GetFullPath(rootPath);
    public string Name => "local";

    private string PathFor(string key)
    {
        var full = Path.GetFullPath(Path.Combine(_root, BlobKeys.Validate(key)));
        return full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal) ? full : throw new ArgumentException("Key escapes the storage root.", nameof(key));
    }

    public async Task PutAsync(string key, Stream content, string? contentType, CancellationToken ct = default)
    {
        var path = PathFor(key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        FileStream file;
        try { file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous); }
        catch (IOException) when (File.Exists(path)) { throw new BlobAlreadyExistsException(key); }
        try { await using (file) await content.CopyToAsync(file, ct); }
        catch { try { File.Delete(path); } catch { } throw; }
        File.SetAttributes(path, FileAttributes.ReadOnly);
    }

    public Task<Stream> OpenReadAsync(string key, CancellationToken ct = default)
    {
        var path = PathFor(key);
        return File.Exists(path) ? Task.FromResult<Stream>(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan)) : throw new BlobNotFoundException(key);
    }

    public Task<long?> GetLengthAsync(string key, CancellationToken ct = default)
    {
        var path = PathFor(key);
        return Task.FromResult<long?>(File.Exists(path) ? new FileInfo(path).Length : null);
    }

    public Task DeleteAsync(string key, CancellationToken ct = default)
    {
        var path = PathFor(key);
        if (File.Exists(path)) { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); }
        return Task.CompletedTask;
    }

    public Task<Uri?> CreateUploadUrlAsync(string key, TimeSpan lifetime, string? contentType, CancellationToken ct = default) => Task.FromResult<Uri?>(null);
    public Task<Uri?> CreateDownloadUrlAsync(string key, TimeSpan lifetime, CancellationToken ct = default) => Task.FromResult<Uri?>(null);
}

public sealed class RemoteServerOptions
{
    /// <summary>Base URL of the storage server: objects live at <c>{BaseAddress}/{key}</c> (PUT/GET/HEAD/DELETE).</summary>
    public Uri BaseAddress { get; set; } = default!;
    public string? BearerToken { get; set; }
    /// <summary>Send <c>If-None-Match: *</c> on PUT so the server refuses to overwrite (immutability).</summary>
    public bool ConditionalCreate { get; set; } = true;
}

/// <summary>Stores blobs on a remote HTTP object server (WebDAV-style verbs). Not a proxy for Wire: plain <see cref="HttpClient"/>.</summary>
public sealed class RemoteServerBlobProvider(HttpClient http, RemoteServerOptions options) : IBlobProvider
{
    public string Name => "remote";

    private HttpRequestMessage Req(HttpMethod m, string key)
    {
        var r = new HttpRequestMessage(m, new Uri(options.BaseAddress.ToString().TrimEnd('/') + "/" + BlobKeys.Validate(key)));
        if (options.BearerToken is not null) r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.BearerToken);
        return r;
    }

    public async Task PutAsync(string key, Stream content, string? contentType, CancellationToken ct = default)
    {
        using var req = Req(HttpMethod.Put, key);
        req.Content = new StreamContent(content);
        if (contentType is not null) req.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        if (options.ConditionalCreate) req.Headers.TryAddWithoutValidation("If-None-Match", "*");
        using var res = await http.SendAsync(req, ct);
        if (res.StatusCode is HttpStatusCode.PreconditionFailed or HttpStatusCode.Conflict) throw new BlobAlreadyExistsException(key);
        res.EnsureSuccessStatusCode();
    }

    public async Task<Stream> OpenReadAsync(string key, CancellationToken ct = default)
    {
        var res = await http.SendAsync(Req(HttpMethod.Get, key), HttpCompletionOption.ResponseHeadersRead, ct);
        if (res.StatusCode == HttpStatusCode.NotFound) { res.Dispose(); throw new BlobNotFoundException(key); }
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsStreamAsync(ct);
    }

    public async Task<long?> GetLengthAsync(string key, CancellationToken ct = default)
    {
        using var res = await http.SendAsync(Req(HttpMethod.Head, key), ct);
        if (res.StatusCode == HttpStatusCode.NotFound) return null;
        res.EnsureSuccessStatusCode();
        return res.Content.Headers.ContentLength;
    }

    public async Task DeleteAsync(string key, CancellationToken ct = default)
    {
        using var res = await http.SendAsync(Req(HttpMethod.Delete, key), ct);
        if (res.StatusCode != HttpStatusCode.NotFound) res.EnsureSuccessStatusCode();
    }

    public Task<Uri?> CreateUploadUrlAsync(string key, TimeSpan lifetime, string? contentType, CancellationToken ct = default) => Task.FromResult<Uri?>(null);
    public Task<Uri?> CreateDownloadUrlAsync(string key, TimeSpan lifetime, CancellationToken ct = default) => Task.FromResult<Uri?>(null);
}
