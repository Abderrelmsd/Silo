using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Bedrock;
using Cipher;
using Cipher.Encryption;
using Cipher.Keys;
using Silo.Data;

namespace Silo;

internal sealed class SiloService(ISiloDbFactory dbf, IBlobProvider provider, IVirusScanner scanner, IEncryptionService encryption, IKeyStore keys,
    ITenantContext tenant, IOptions<SiloOptions> options, TimeProvider time, ILogger<SiloService> logger) : ISilo
{
    private readonly SiloOptions _o = options.Value;

    private sealed class Spool(FileStream stream, long length, string sha256) : IAsyncDisposable
    {
        public FileStream Stream { get; } = stream;
        public long Length { get; } = length;
        public string Sha256 { get; } = sha256;
        public ValueTask DisposeAsync() => Stream.DisposeAsync();
    }

    // ---- upload --------------------------------------------------------------------------------------------

    public async Task<SiloObject> UploadAsync(UploadRequest request, Stream content, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        var fileName = SanitizeFileName(request.FileName);
        await using var spool = await SpoolAsync(content, ct);

        var (source, scannedAt) = await ScanInline(spool.Stream, ct);
        var id = Guid.NewGuid();
        var key = KeyFor(tenantId, id);

        spool.Stream.Position = 0;
        if (_o.EncryptAtRest)
        {
            await EnsureKey(ct);
            await using var cipherFile = NewTempFile();
            await ChunkedEncryption.EncryptAsync(encryption, _o.EncryptionKeyId, spool.Stream, cipherFile, id, _o.EncryptionChunkBytes, ct);
            cipherFile.Position = 0;
            await provider.PutAsync(key, cipherFile, request.ContentType, ct);
        }
        else await provider.PutAsync(key, spool.Stream, request.ContentType, ct);

        try
        {
            return await Insert(id, tenantId, fileName, request.ContentType, spool.Length, spool.Sha256, SiloObjectStatus.Clean, source, scannedAt,
                _o.EncryptAtRest, request.SupersedesId, request.CreatedBy, request.OwnerTags, ct);
        }
        catch
        {
            await SafeDelete(key); // no orphan blob if the metadata write fails
            throw;
        }
    }

    public async Task<SiloObject> ReplaceAsync(Guid existingObjectId, UploadRequest request, Stream content, CancellationToken ct = default)
    {
        if (await GetAsync(existingObjectId, ct) is null) throw new ObjectNotFoundException(existingObjectId);
        return await UploadAsync(new UploadRequest
        {
            FileName = request.FileName, ContentType = request.ContentType, CreatedBy = request.CreatedBy, OwnerTags = request.OwnerTags, SupersedesId = existingObjectId,
        }, content, ct);
    }

    private async Task<(string Source, DateTimeOffset ScannedAt)> ScanInline(Stream spool, CancellationToken ct)
    {
        try
        {
            spool.Position = 0;
            var result = await scanner.ScanAsync(spool, ct);
            if (result is ScanResult.Infected inf)
            {
                logger.LogWarning("Upload rejected by {Engine}: {Signature}", inf.Engine, inf.Signature);
                throw new InfectedContentException(inf.Signature);
            }
            return ("inline:" + scanner.Name, time.GetUtcNow());
        }
        catch (Exception ex) when (ex is not (InfectedContentException or OperationCanceledException))
        {
            logger.LogError(ex, "Virus scanner {Scanner} failed", scanner.Name);
            if (_o.RejectWhenScannerFails) throw new ScanUnavailableException("The virus scanner is unavailable; upload rejected.", ex);
            return ("unscanned", time.GetUtcNow());
        }
    }

    // ---- direct upload -------------------------------------------------------------------------------------

    public async Task<DirectUploadTicket> BeginDirectUploadAsync(DirectUploadRequest request, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        if (!_o.AllowDirectUpload) throw new DirectUploadNotAllowedException("Direct uploads are disabled; upload through Silo so content is scanned inline.");
        if (request.ClientScan is null) throw new DirectUploadNotAllowedException("Direct uploads bypass inline scanning and require a client scan attestation.");
        if (string.IsNullOrWhiteSpace(request.ClientScan.Scanner)) throw new DirectUploadNotAllowedException("The scan attestation must name the scanner used.");
        if (_o.EncryptAtRest) throw new DirectUploadNotAllowedException("Direct uploads can't be encrypted at rest; disable EncryptAtRest or upload through Silo.");

        var fileName = SanitizeFileName(request.FileName);
        var id = Guid.NewGuid();
        var lifetime = request.UrlLifetime ?? _o.DirectUploadUrlLifetime;
        var url = await provider.CreateUploadUrlAsync(KeyFor(tenantId, id), lifetime, request.ContentType, ct)
            ?? throw new DirectUploadNotAllowedException($"The '{provider.Name}' provider doesn't support direct uploads.");

        var scan = request.ClientScan;
        await Insert(id, tenantId, fileName, request.ContentType, 0, "", SiloObjectStatus.PendingDirectUpload,
            $"client:{scan.Scanner}{(scan.Version is null ? "" : "/" + scan.Version)}", scan.ScannedAt, false, null, request.CreatedBy, request.OwnerTags, ct);
        return new DirectUploadTicket(id, url, time.GetUtcNow() + lifetime);
    }

    public async Task<SiloObject> CompleteDirectUploadAsync(Guid objectId, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId && o.Status == SiloObjectStatus.PendingDirectUpload, ct) ?? throw new ObjectNotFoundException(objectId);
        var key = KeyFor(tenantId, objectId);

        var length = await provider.GetLengthAsync(key, ct) ?? throw new SiloException("The upload has not arrived at the storage provider yet.");
        if (length > _o.MaxObjectBytes)
        {
            db.Objects.Remove(row);
            await db.SaveChangesAsync(ct);
            await SafeDelete(key);
            throw new ObjectTooLargeException(_o.MaxObjectBytes);
        }

        await using var blob = await provider.OpenReadAsync(key, ct);
        row.Sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(blob, ct));
        row.Length = length;
        row.Status = SiloObjectStatus.Clean;
        await db.SaveChangesAsync(ct);
        return await Map(db, row, ct);
    }

    public async Task<int> ExpirePendingDirectUploadsAsync(DateTimeOffset olderThan, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var rows = await db.Objects.Where(o => o.Status == SiloObjectStatus.PendingDirectUpload && o.CreatedAt < olderThan).ToListAsync(ct);
        foreach (var r in rows)
        {
            db.Owners.RemoveRange(await db.Owners.Where(x => x.ObjectId == r.Id).ToListAsync(ct));
            db.Objects.Remove(r);
        }
        await db.SaveChangesAsync(ct);
        foreach (var r in rows) await SafeDelete(KeyFor(tenantId, r.Id));
        return rows.Count;
    }

    // ---- read ----------------------------------------------------------------------------------------------

    public async Task<SiloObject?> GetAsync(Guid objectId, CancellationToken ct = default)
    {
        SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId, ct);
        return row is null ? null : await Map(db, row, ct);
    }

    public async Task<SiloReadResult?> OpenReadAsync(Guid objectId, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId && o.Status == SiloObjectStatus.Clean, ct);
        if (row is null) return null;

        var meta = await Map(db, row, ct);
        var stream = await provider.OpenReadAsync(KeyFor(tenantId, objectId), ct);
        return new SiloReadResult(meta, row.Encrypted ? ChunkedEncryption.Decrypt(encryption, _o.EncryptionKeyId, stream, objectId) : stream);
    }

    public async Task<Uri?> CreateDownloadUrlAsync(Guid objectId, TimeSpan lifetime, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId && o.Status == SiloObjectStatus.Clean, ct);
        return row is null || row.Encrypted ? null : await provider.CreateDownloadUrlAsync(KeyFor(tenantId, objectId), lifetime, ct);
    }

    // ---- ownership -----------------------------------------------------------------------------------------

    public async Task ClaimAsync(Guid objectId, string ownerType, string ownerId, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        if (string.IsNullOrWhiteSpace(ownerType) || string.IsNullOrWhiteSpace(ownerId)) throw new ArgumentException("Owner type and id are required.");
        await using var db = dbf.CreateTenant();
        if (!await db.Objects.AnyAsync(o => o.Id == objectId, ct)) throw new ObjectNotFoundException(objectId);

        var row = await db.Owners.SingleOrDefaultAsync(o => o.ObjectId == objectId && o.OwnerType == ownerType && o.OwnerId == ownerId, ct);
        if (row is null) db.Owners.Add(row = new SiloOwnerRow { ObjectId = objectId, OwnerType = ownerType, OwnerId = ownerId, TenantId = tenantId });
        row.Claimed = true;
        row.ClaimedAt ??= time.GetUtcNow();
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SiloObject>> FindByOwnerAsync(string ownerType, string ownerId, CancellationToken ct = default)
    {
        SafeTenant();
        await using var db = dbf.CreateTenant();
        var ids = await db.Owners.Where(o => o.OwnerType == ownerType && o.OwnerId == ownerId).Select(o => o.ObjectId).ToListAsync(ct);
        var rows = await db.Objects.Where(o => ids.Contains(o.Id)).OrderBy(o => o.CreatedAt).ToListAsync(ct);
        return await MapMany(db, rows, ct);
    }

    public async Task<IReadOnlyList<SiloObject>> ListUnclaimedAsync(DateTimeOffset olderThan, int take = 100, CancellationToken ct = default)
    {
        SafeTenant();
        await using var db = dbf.CreateTenant();
        var claimed = await db.Owners.Where(o => o.Claimed).Select(o => o.ObjectId).Distinct().ToListAsync(ct);
        var rows = await db.Objects.Where(o => o.Status == SiloObjectStatus.Clean && o.CreatedAt < olderThan && !claimed.Contains(o.Id))
            .OrderBy(o => o.CreatedAt).Take(Math.Clamp(take, 1, 1000)).ToListAsync(ct);
        return await MapMany(db, rows, ct);
    }

    // ---- maintenance ---------------------------------------------------------------------------------------

    public async Task<ScanResult> RescanAsync(Guid objectId, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId, ct) ?? throw new ObjectNotFoundException(objectId);
        await using var plain = await OpenPlain(tenantId, row, ct);
        await using var spool = await SpoolAsync(plain, ct);
        spool.Stream.Position = 0;

        var result = await scanner.ScanAsync(spool.Stream, ct);
        if (result is ScanResult.Infected inf)
        {
            row.Status = SiloObjectStatus.Quarantined;
            logger.LogWarning("Object {Id} quarantined by rescan: {Signature}", objectId, inf.Signature);
        }
        else { row.ScanSource = "rescan:" + scanner.Name; row.ScannedAt = time.GetUtcNow(); }
        await db.SaveChangesAsync(ct);
        return result;
    }

    public async Task<bool> VerifyIntegrityAsync(Guid objectId, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId, ct) ?? throw new ObjectNotFoundException(objectId);
        try
        {
            await using var plain = await OpenPlain(tenantId, row, ct);
            return Convert.ToHexStringLower(await SHA256.HashDataAsync(plain, ct)) == row.Sha256;
        }
        catch (CipherDecryptionException) { return false; }
    }

    public async Task PurgeAsync(Guid objectId, CancellationToken ct = default)
    {
        var tenantId = SafeTenant();
        await using var db = dbf.CreateTenant();
        var row = await db.Objects.SingleOrDefaultAsync(o => o.Id == objectId, ct) ?? throw new ObjectNotFoundException(objectId);
        db.Owners.RemoveRange(await db.Owners.Where(o => o.ObjectId == objectId).ToListAsync(ct));
        db.Objects.Remove(row);
        await db.SaveChangesAsync(ct); // metadata first: a leaked blob is harmless, a dangling reference is not
        await SafeDelete(KeyFor(tenantId, objectId));
    }

    // ---- helpers -------------------------------------------------------------------------------------------

    private async Task<Stream> OpenPlain(string tenantId, SiloObjectRow row, CancellationToken ct)
    {
        var stream = await provider.OpenReadAsync(KeyFor(tenantId, row.Id), ct);
        return row.Encrypted ? ChunkedEncryption.Decrypt(encryption, _o.EncryptionKeyId, stream, row.Id) : stream;
    }

    private async Task<SiloObject> Insert(Guid id, string tenantId, string fileName, string? contentType, long length, string sha256, SiloObjectStatus status,
        string scanSource, DateTimeOffset? scannedAt, bool encrypted, Guid? supersedes, string? createdBy, IReadOnlyList<OwnerRef>? tags, CancellationToken ct)
    {
        await using var db = dbf.CreateTenant();
        var row = new SiloObjectRow
        {
            Id = id, TenantId = tenantId, FileName = fileName, ContentType = SanitizeContentType(contentType), Length = length, Sha256 = sha256, Status = status,
            ScanSource = scanSource, ScannedAt = scannedAt, Encrypted = encrypted, SupersedesId = supersedes, CreatedAt = time.GetUtcNow(), CreatedBy = createdBy,
        };
        db.Objects.Add(row);
        foreach (var t in (tags ?? []).DistinctBy(t => (t.Type, t.Id)))
            db.Owners.Add(new SiloOwnerRow { ObjectId = id, OwnerType = t.Type, OwnerId = t.Id, TenantId = tenantId }); // passive: unclaimed until ClaimAsync
        await db.SaveChangesAsync(ct);
        return await Map(db, row, ct);
    }

    private static async Task<SiloObject> Map(SiloDb db, SiloObjectRow r, CancellationToken ct)
        => (await MapMany(db, [r], ct))[0];

    private static async Task<IReadOnlyList<SiloObject>> MapMany(SiloDb db, List<SiloObjectRow> rows, CancellationToken ct)
    {
        var ids = rows.Select(r => r.Id).ToList();
        var owners = (await db.Owners.Where(o => ids.Contains(o.ObjectId)).ToListAsync(ct)).ToLookup(o => o.ObjectId);
        return [.. rows.Select(r => new SiloObject(r.Id, r.TenantId, r.FileName, r.ContentType, r.Length, r.Sha256, r.Status, r.ScanSource, r.ScannedAt, r.Encrypted,
            r.SupersedesId, r.CreatedAt, r.CreatedBy, [.. owners[r.Id].OrderBy(o => o.OwnerType).ThenBy(o => o.OwnerId).Select(o => new SiloOwner(o.OwnerType, o.OwnerId, o.Claimed, o.ClaimedAt))]))];
    }

    private async Task<Spool> SpoolAsync(Stream content, CancellationToken ct)
    {
        var file = NewTempFile();
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81920];
            long total = 0;
            int n;
            while ((n = await content.ReadAsync(buffer, ct)) > 0)
            {
                total += n;
                if (total > _o.MaxObjectBytes) throw new ObjectTooLargeException(_o.MaxObjectBytes);
                hash.AppendData(buffer, 0, n);
                await file.WriteAsync(buffer.AsMemory(0, n), ct);
            }
            await file.FlushAsync(ct);
            file.Position = 0;
            return new Spool(file, total, Convert.ToHexStringLower(hash.GetHashAndReset()));
        }
        catch { await file.DisposeAsync(); throw; }
    }

    private static FileStream NewTempFile()
        => new(Path.Combine(Path.GetTempPath(), "silo-" + Guid.NewGuid().ToString("N")), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920,
            FileOptions.Asynchronous | FileOptions.DeleteOnClose);

    private string SafeTenant()
    {
        var t = tenant.RequireTenantId();
        if (t.Length == 0 || !t.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) throw new SiloException($"Tenant id '{t}' can't be used in storage keys.");
        return t;
    }

    private static string KeyFor(string tenantId, Guid id) => $"{tenantId}/{id:N}";

    private async Task SafeDelete(string key)
    {
        try { await provider.DeleteAsync(key); }
        catch (Exception ex) { logger.LogWarning(ex, "Could not delete blob {Key}", key); }
    }

    private async Task EnsureKey(CancellationToken ct)
    {
        try { await keys.GetActiveAsync(_o.EncryptionKeyId, ct); }
        catch (CipherKeyNotFoundException) { await keys.RotateAsync(_o.EncryptionKeyId, KeyKind.Symmetric, ct); }
    }

    internal static string SanitizeFileName(string? name)
    {
        var n = Path.GetFileName((name ?? "").Replace('\\', '/'));
        n = new string(n.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (n.Length == 0) throw new ArgumentException("A file name is required.");
        return n.Length > 255 ? n[..255] : n;
    }

    internal static string SanitizeContentType(string? ct)
        => !string.IsNullOrWhiteSpace(ct) && ct.Length <= 200 && ct.Contains('/') && ct.All(c => c >= ' ' && c < 127) ? ct.Trim() : "application/octet-stream";
}
