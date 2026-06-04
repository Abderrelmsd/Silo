using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Bedrock;
using Cipher;
using Silo.Data;
using Silo.Providers;

namespace Silo.Tests;

public sealed class FakeTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

internal sealed class InMemorySiloDb(InMemoryDatabaseRoot root, string name, ITenantContext ambient) : ISiloDbFactory
{
    public SiloDb CreateTenant() => new(new DbContextOptionsBuilder<SiloDb>().UseInMemoryDatabase(name, root).AddInterceptors(new TenantSaveChangesInterceptor(ambient)).Options, ambient);
}

/// <summary>A tiny HTTP object server (PUT/GET/HEAD/DELETE with If-None-Match: *).</summary>
public sealed class ObjectServerHandler : HttpMessageHandler
{
    public Dictionary<string, byte[]> Store { get; } = [];
    public List<string?> AuthHeaders { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
    {
        AuthHeaders.Add(r.Headers.Authorization?.ToString());
        var key = r.RequestUri!.AbsolutePath.TrimStart('/');
        if (r.Method == HttpMethod.Put)
        {
            if (r.Headers.Contains("If-None-Match") && Store.ContainsKey(key)) return new HttpResponseMessage(HttpStatusCode.PreconditionFailed);
            Store[key] = await r.Content!.ReadAsByteArrayAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.Created);
        }
        if (!Store.TryGetValue(key, out var bytes)) return new HttpResponseMessage(HttpStatusCode.NotFound);
        if (r.Method == HttpMethod.Delete) { Store.Remove(key); return new HttpResponseMessage(HttpStatusCode.NoContent); }
        var res = new HttpResponseMessage(HttpStatusCode.OK);
        if (r.Method == HttpMethod.Get) res.Content = new ByteArrayContent(bytes);
        else { res.Content = new ByteArrayContent([]); res.Content.Headers.ContentLength = bytes.Length; }
        return res;
    }
}

public sealed class Env : IAsyncDisposable
{
    public FakeTime Time { get; } = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    public ServiceProvider Sp { get; }
    public ISilo Silo => Sp.GetRequiredService<ISilo>();
    public ITenantContextAccessor Tenants => Sp.GetRequiredService<ITenantContextAccessor>();
    public IBlobProvider Provider => Sp.GetRequiredService<IBlobProvider>();
    public InMemoryBlobProvider Memory => (InMemoryBlobProvider)Provider;
    public string? TempDir { get; }

    public Env(string provider = "memory", Action<SiloOptions>? configure = null, Action<IServiceCollection>? more = null, ObjectServerHandler? server = null)
    {
        var s = new ServiceCollection();
        s.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        s.AddSingleton<TimeProvider>(Time);
        s.AddCipher();
        var ambient = new AmbientTenantContext();
        s.AddSingleton(ambient); s.AddSingleton<ITenantContextAccessor>(ambient); s.AddSingleton<ITenantContext>(ambient);
        s.AddSingleton<ISiloDbFactory>(new InMemorySiloDb(new InMemoryDatabaseRoot(), Guid.NewGuid().ToString(), ambient));
        s.AddSilo(configure);
        switch (provider)
        {
            case "memory": s.AddSiloInMemory(); break;
            case "local":
                TempDir = Path.Combine(Path.GetTempPath(), "silo-tests-" + Guid.NewGuid().ToString("N"));
                s.AddSiloLocalFileSystem(TempDir); break;
            case "remote":
                s.AddSiloRemoteServer(o => { o.BaseAddress = new Uri("https://store.test/blobs"); o.BearerToken = "tok"; }, server ?? new ObjectServerHandler()); break;
        }
        more?.Invoke(s);
        Sp = s.BuildServiceProvider();
    }

    public static UploadRequest Req(string name = "a.txt", string? type = "text/plain", params OwnerRef[] tags) => new() { FileName = name, ContentType = type, CreatedBy = "u1", OwnerTags = tags };
    public static MemoryStream Bytes(string s) => new(Encoding.UTF8.GetBytes(s));
    public static async Task<byte[]> ReadAll(SiloReadResult r) { await using var _ = r; using var ms = new MemoryStream(); await r.Content.CopyToAsync(ms); return ms.ToArray(); }

    public async ValueTask DisposeAsync()
    {
        await Sp.DisposeAsync();
        if (TempDir is not null && Directory.Exists(TempDir))
        {
            foreach (var f in Directory.EnumerateFiles(TempDir, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(TempDir, true);
        }
    }
}

public class StorageTests
{
    public static TheoryData<string> Providers => new() { "memory", "local", "remote" };

    [Theory, MemberData(nameof(Providers))]
    public async Task Upload_then_read_roundtrips_with_metadata_on_every_provider(string provider)
    {
        await using var env = new Env(provider);
        using var _ = env.Tenants.Use("acme");
        var payload = new byte[300_000]; new Random(7).NextBytes(payload);

        var obj = await env.Silo.UploadAsync(Env.Req("report.pdf", "application/pdf"), new MemoryStream(payload));

        Assert.Equal(("report.pdf", "application/pdf", 300_000L, SiloObjectStatus.Clean), (obj.FileName, obj.ContentType, obj.Length, obj.Status));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(payload)), obj.Sha256);
        Assert.StartsWith("inline:", obj.ScanSource);
        Assert.Equal(payload, await Env.ReadAll((await env.Silo.OpenReadAsync(obj.Id))!));
        Assert.True(await env.Silo.VerifyIntegrityAsync(obj.Id));
    }

    [Fact]
    public async Task Provider_keys_are_opaque_and_tenant_prefixed()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var obj = await env.Silo.UploadAsync(Env.Req("secret-plans.docx"), Env.Bytes("x"));
        var key = Assert.Single(env.Memory.Keys);
        Assert.Equal($"acme/{obj.Id:N}", key);
        Assert.DoesNotContain("secret", key);
    }

    [Fact]
    public async Task Tenants_cannot_see_touch_or_delete_each_others_objects()
    {
        await using var env = new Env();
        Guid id;
        using (env.Tenants.Use("acme")) id = (await env.Silo.UploadAsync(Env.Req(), Env.Bytes("acme data"))).Id;

        using (env.Tenants.Use("globex"))
        {
            Assert.Null(await env.Silo.GetAsync(id));
            Assert.Null(await env.Silo.OpenReadAsync(id));
            Assert.Null(await env.Silo.CreateDownloadUrlAsync(id, TimeSpan.FromMinutes(1)));
            await Assert.ThrowsAsync<ObjectNotFoundException>(() => env.Silo.PurgeAsync(id));
            await Assert.ThrowsAsync<ObjectNotFoundException>(() => env.Silo.ClaimAsync(id, "doc", "1"));
            Assert.Empty(await env.Silo.ListUnclaimedAsync(env.Time.Now.AddDays(1)));
        }
        using (env.Tenants.Use("acme")) Assert.NotNull(await env.Silo.OpenReadAsync(id));
        await Assert.ThrowsAsync<TenantContextMissingException>(() => env.Silo.GetAsync(id));
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Providers_refuse_to_overwrite_because_objects_are_immutable(string provider)
    {
        await using var env = new Env(provider);
        await env.Provider.PutAsync("acme/abc123", Env.Bytes("v1"), null);
        await Assert.ThrowsAsync<BlobAlreadyExistsException>(() => env.Provider.PutAsync("acme/abc123", Env.Bytes("v2"), null));
        using var read = await env.Provider.OpenReadAsync("acme/abc123");
        Assert.Equal("v1", await new StreamReader(read).ReadToEndAsync());
        await Assert.ThrowsAsync<BlobNotFoundException>(() => env.Provider.OpenReadAsync("acme/missing"));
        Assert.Null(await env.Provider.GetLengthAsync("acme/missing"));
    }

    [Fact]
    public async Task Replace_creates_a_new_object_and_leaves_the_old_one_untouched()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var v1 = await env.Silo.UploadAsync(Env.Req("doc.txt"), Env.Bytes("version 1"));
        var v2 = await env.Silo.ReplaceAsync(v1.Id, Env.Req("doc.txt"), Env.Bytes("version 2"));

        Assert.NotEqual(v1.Id, v2.Id);
        Assert.Equal(v1.Id, v2.SupersedesId);
        Assert.Equal("version 1", Encoding.UTF8.GetString(await Env.ReadAll((await env.Silo.OpenReadAsync(v1.Id))!)));
        Assert.Equal("version 2", Encoding.UTF8.GetString(await Env.ReadAll((await env.Silo.OpenReadAsync(v2.Id))!)));
        await Assert.ThrowsAsync<ObjectNotFoundException>(() => env.Silo.ReplaceAsync(Guid.NewGuid(), Env.Req(), Env.Bytes("x")));
    }

    [Fact]
    public async Task Path_traversal_and_odd_names_cannot_escape_storage_or_pollute_metadata()
    {
        await using var env = new Env("local");
        using var _ = env.Tenants.Use("acme");
        var obj = await env.Silo.UploadAsync(Env.Req("..\\..\\etc/passwd", "text/x\r\nInjected: 1"), Env.Bytes("x"));
        Assert.Equal("passwd", obj.FileName);
        Assert.Equal("application/octet-stream", obj.ContentType);
        await Assert.ThrowsAsync<ArgumentException>(() => env.Silo.UploadAsync(Env.Req("  "), Env.Bytes("x")));

        var provider = new LocalFileSystemBlobProvider(env.TempDir!);
        foreach (var bad in new[] { "../x", "acme/../../x", "/etc/passwd", "a//b", "acme/.." })
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.PutAsync(bad, Env.Bytes("x"), null));

        Directory.GetFiles(env.TempDir!, "*", SearchOption.AllDirectories).ToList().ForEach(f => Assert.StartsWith(env.TempDir!, f));
    }

    [Fact]
    public async Task Size_limit_is_enforced_while_streaming()
    {
        await using var env = new Env(configure: o => o.MaxObjectBytes = 1000);
        using var _ = env.Tenants.Use("acme");
        await Assert.ThrowsAsync<ObjectTooLargeException>(() => env.Silo.UploadAsync(Env.Req(), new MemoryStream(new byte[1001])));
        Assert.Empty(env.Memory.Keys);
        await env.Silo.UploadAsync(Env.Req(), new MemoryStream(new byte[1000]));
    }

    [Fact]
    public async Task Purge_removes_blob_and_metadata_permanently()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var obj = await env.Silo.UploadAsync(Env.Req("a.txt", null, new OwnerRef("doc", "1")), Env.Bytes("bye"));
        await env.Silo.PurgeAsync(obj.Id);
        Assert.Empty(env.Memory.Keys);
        Assert.Null(await env.Silo.GetAsync(obj.Id));
        Assert.Empty(await env.Silo.FindByOwnerAsync("doc", "1"));
    }

    [Fact]
    public async Task Remote_provider_sends_credentials_and_maps_statuses()
    {
        var server = new ObjectServerHandler();
        await using var env = new Env("remote", server: server);
        using var _ = env.Tenants.Use("acme");
        var obj = await env.Silo.UploadAsync(Env.Req(), Env.Bytes("remote"));
        Assert.Contains($"acme/{obj.Id:N}", server.Store.Keys.Select(k => k.Replace("blobs/", "")));
        Assert.All(server.AuthHeaders, h => Assert.Equal("Bearer tok", h));
        Assert.Equal(6, await env.Provider.GetLengthAsync($"acme/{obj.Id:N}"));
        await env.Silo.PurgeAsync(obj.Id);
        Assert.Empty(server.Store);
    }
}

public class ScanningTests
{
    private static byte[] WithEicarAt(int offset, int total)
    {
        var data = new byte[total];
        new Random(3).NextBytes(data);
        for (var i = 0; i < data.Length; i++) data[i] = (byte)('a' + data[i] % 26);
        Encoding.ASCII.GetBytes(BasicSignatureScanner.EicarSignature).CopyTo(data, offset);
        return data;
    }

    [Fact]
    public async Task Eicar_upload_is_rejected_and_nothing_is_stored()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var ex = await Assert.ThrowsAsync<InfectedContentException>(() => env.Silo.UploadAsync(Env.Req("virus.com"), Env.Bytes(BasicSignatureScanner.EicarSignature)));
        Assert.Equal("Eicar-Test-Signature", ex.Signature);
        Assert.Empty(env.Memory.Keys);
        Assert.Empty(await env.Silo.ListUnclaimedAsync(env.Time.Now.AddDays(1)));
    }

    [Theory]
    [InlineData(10)]
    [InlineData(64 * 1024 - 20)]   // straddles the scanner's read boundary
    [InlineData(64 * 1024 + 500)]
    [InlineData(300_000)]
    public async Task Signatures_are_found_wherever_they_sit_including_across_read_boundaries(int offset)
    {
        var scanner = new BasicSignatureScanner();
        var data = WithEicarAt(offset, offset + 70 + 1000);
        Assert.IsType<ScanResult.Infected>(await scanner.ScanAsync(new MemoryStream(data)));
        Assert.IsType<ScanResult.Clean>(await scanner.ScanAsync(new MemoryStream(Encoding.ASCII.GetBytes(new string('a', 200_000)))));
    }

    [Fact]
    public async Task Custom_signatures_ascii_and_hex()
    {
        var scanner = new BasicSignatureScanner(new Dictionary<string, string> { ["Evil.Ascii"] = "EVIL-PAYLOAD", ["Evil.Hex"] = "hex:DEADBEEF00" });
        Assert.Equal("Evil.Ascii", ((ScanResult.Infected)await scanner.ScanAsync(Env.Bytes("xx EVIL-PAYLOAD yy"))).Signature);
        Assert.Equal("Evil.Hex", ((ScanResult.Infected)await scanner.ScanAsync(new MemoryStream([1, 0xDE, 0xAD, 0xBE, 0xEF, 0, 2]))).Signature);
        Assert.IsType<ScanResult.Clean>(await scanner.ScanAsync(new MemoryStream([1, 2, 3])));
    }

    private sealed class BrokenScanner : IVirusScanner
    {
        public string Name => "broken";
        public Task<ScanResult> ScanAsync(Stream content, CancellationToken ct = default) => throw new IOException("clamd down");
    }

    [Fact]
    public async Task Scanner_failure_fails_closed_unless_configured_otherwise()
    {
        await using var closed = new Env(more: s => s.AddSingleton<IVirusScanner, BrokenScanner>());
        using (closed.Tenants.Use("acme"))
        {
            await Assert.ThrowsAsync<ScanUnavailableException>(() => closed.Silo.UploadAsync(Env.Req(), Env.Bytes("x")));
            Assert.Empty(closed.Memory.Keys);
        }
        await using var open = new Env(configure: o => o.RejectWhenScannerFails = false, more: s => s.AddSingleton<IVirusScanner, BrokenScanner>());
        using (open.Tenants.Use("acme"))
            Assert.Equal("unscanned", (await open.Silo.UploadAsync(Env.Req(), Env.Bytes("x"))).ScanSource);
    }

    private sealed class FakeClamConnection(byte[] reply) : Stream
    {
        public MemoryStream Sent { get; } = new();
        private int _pos;
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] b, int o, int c) { var n = Math.Min(c, reply.Length - _pos); Array.Copy(reply, _pos, b, o, n); _pos += n; return n; }
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();
        public override void Write(byte[] b, int o, int c) => Sent.Write(b, o, c);
    }

    [Fact]
    public async Task ClamAv_speaks_instream_and_parses_replies()
    {
        var conn = new FakeClamConnection(Encoding.ASCII.GetBytes("stream: OK\0"));
        var clean = await new ClamAvScanner(_ => Task.FromResult<Stream>(conn), chunkBytes: 4).ScanAsync(new MemoryStream("abcdefghij"u8.ToArray()));
        Assert.IsType<ScanResult.Clean>(clean);

        var sent = conn.Sent.ToArray();
        Assert.Equal("zINSTREAM\0", Encoding.ASCII.GetString(sent, 0, 10));
        // chunks of 4,4,2 (each prefixed by a big-endian length), then a zero-length terminator
        Assert.Equal("00000004" + "61626364" + "00000004" + "65666768" + "00000002" + "696a" + "00000000", Convert.ToHexStringLower(sent[10..]));

        var found = await new ClamAvScanner(_ => Task.FromResult<Stream>(new FakeClamConnection(Encoding.ASCII.GetBytes("stream: Win.Test.EICAR_HDB-1 FOUND\0")))).ScanAsync(Env.Bytes("x"));
        Assert.Equal("Win.Test.EICAR_HDB-1", ((ScanResult.Infected)found).Signature);
        await Assert.ThrowsAsync<ScanUnavailableException>(() => new ClamAvScanner(_ => Task.FromResult<Stream>(new FakeClamConnection(Encoding.ASCII.GetBytes("INSTREAM size limit exceeded. ERROR\0")))).ScanAsync(Env.Bytes("x")));
    }

    [Fact]
    public async Task Rescan_quarantines_objects_that_later_turn_out_infected()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        var obj = await env.Silo.UploadAsync(Env.Req(), Env.Bytes("looks fine"));
        Assert.IsType<ScanResult.Clean>(await env.Silo.RescanAsync(obj.Id));
        Assert.StartsWith("rescan:", (await env.Silo.GetAsync(obj.Id))!.ScanSource);

        env.Memory.SimulateDirectUpload($"acme/{obj.Id:N}", Encoding.ASCII.GetBytes(BasicSignatureScanner.EicarSignature)); // e.g. a signature update finds it later
        Assert.IsType<ScanResult.Infected>(await env.Silo.RescanAsync(obj.Id));
        Assert.Equal(SiloObjectStatus.Quarantined, (await env.Silo.GetAsync(obj.Id))!.Status);
        Assert.Null(await env.Silo.OpenReadAsync(obj.Id)); // never readable again
    }
}

public class EncryptionTests
{
    private static Env Encrypted(int chunk = 1024) => new(configure: o => { o.EncryptAtRest = true; o.EncryptionChunkBytes = chunk; });

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1024)]      // exactly one full chunk
    [InlineData(1025)]
    [InlineData(10_000)]
    public async Task Encrypted_objects_roundtrip_across_chunk_sizes_and_are_not_plaintext_at_rest(int size)
    {
        await using var env = Encrypted();
        using var _ = env.Tenants.Use("acme");
        var data = Enumerable.Range(0, size).Select(i => (byte)(i % 251)).ToArray();
        if (size >= 16) Encoding.ASCII.GetBytes("PLAINTEXT-MARKER").CopyTo(data, 0);

        var obj = await env.Silo.UploadAsync(Env.Req(), new MemoryStream(data));

        Assert.True(obj.Encrypted);
        Assert.Equal(size, obj.Length);
        var raw = env.Memory.Raw($"acme/{obj.Id:N}")!;
        if (size >= 16) Assert.False(raw.AsSpan().IndexOf("PLAINTEXT-MARKER"u8) >= 0);
        Assert.Equal(data, await Env.ReadAll((await env.Silo.OpenReadAsync(obj.Id))!));
        Assert.True(await env.Silo.VerifyIntegrityAsync(obj.Id));
        Assert.Null(await env.Silo.CreateDownloadUrlAsync(obj.Id, TimeSpan.FromMinutes(1))); // ciphertext must not be handed out
    }

    [Fact]
    public async Task Tampering_truncation_and_swapping_are_detected()
    {
        await using var env = Encrypted();
        using var _ = env.Tenants.Use("acme");
        var a = await env.Silo.UploadAsync(Env.Req(), new MemoryStream(new byte[5000]));
        var b = await env.Silo.UploadAsync(Env.Req(), new MemoryStream(new byte[5000]));
        var keyA = $"acme/{a.Id:N}";
        var raw = env.Memory.Raw(keyA)!;

        // flipped bit
        var flipped = (byte[])raw.Clone(); flipped[^5] ^= 1;
        env.Memory.SimulateDirectUpload(keyA, flipped);
        Assert.False(await env.Silo.VerifyIntegrityAsync(a.Id));

        // last chunk dropped (truncation)
        var frameCount = 0; var pos = 6;
        var starts = new List<int>();
        while (pos < raw.Length) { starts.Add(pos); pos += 4 + System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(raw.AsSpan(pos)); frameCount++; }
        env.Memory.SimulateDirectUpload(keyA, raw[..starts[^1]]);
        await using (var r = (await env.Silo.OpenReadAsync(a.Id))!) await Assert.ThrowsAsync<CipherDecryptionException>(() => r.Content.CopyToAsync(Stream.Null));

        // ciphertext of another object
        env.Memory.SimulateDirectUpload(keyA, env.Memory.Raw($"acme/{b.Id:N}")!);
        await using (var r = (await env.Silo.OpenReadAsync(a.Id))!) await Assert.ThrowsAsync<CipherDecryptionException>(() => r.Content.CopyToAsync(Stream.Null));
        Assert.True(frameCount > 2);
    }

    [Fact]
    public async Task Key_rotation_keeps_old_objects_readable()
    {
        await using var env = Encrypted();
        using var _ = env.Tenants.Use("acme");
        var obj = await env.Silo.UploadAsync(Env.Req(), new MemoryStream(new byte[3000]));
        await env.Sp.GetRequiredService<Cipher.Keys.IKeyStore>().RotateAsync("silo-content");
        var newer = await env.Silo.UploadAsync(Env.Req(), new MemoryStream(new byte[10]));
        Assert.True(await env.Silo.VerifyIntegrityAsync(obj.Id));
        Assert.True(await env.Silo.VerifyIntegrityAsync(newer.Id));
    }
}

public class DirectUploadAndOwnershipTests
{
    private static readonly ClientScanAttestation Scan = new("clamav", "1.0", new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    private static Env Direct(Action<SiloOptions>? cfg = null) => new(configure: o => { o.AllowDirectUpload = true; cfg?.Invoke(o); }, more: s => { });

    [Fact]
    public async Task Direct_upload_is_refused_unless_enabled_attested_unencrypted_and_supported()
    {
        await using (var off = new Env())
        {
            off.Memory.UploadUrlBase = new Uri("https://up.test/");
            using var _ = off.Tenants.Use("acme");
            await Assert.ThrowsAsync<DirectUploadNotAllowedException>(() => off.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "a", ClientScan = Scan }));
        }
        await using (var env = Direct())
        {
            env.Memory.UploadUrlBase = new Uri("https://up.test/");
            using var _ = env.Tenants.Use("acme");
            await Assert.ThrowsAsync<DirectUploadNotAllowedException>(() => env.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "a" }));                       // no attestation
            await Assert.ThrowsAsync<DirectUploadNotAllowedException>(() => env.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "a", ClientScan = Scan with { Scanner = " " } }));
        }
        await using (var enc = Direct(o => o.EncryptAtRest = true))
        {
            enc.Memory.UploadUrlBase = new Uri("https://up.test/");
            using var _ = enc.Tenants.Use("acme");
            await Assert.ThrowsAsync<DirectUploadNotAllowedException>(() => enc.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "a", ClientScan = Scan }));
        }
        await using (var noUrls = Direct()) // in-memory provider without an upload URL base = provider can't do direct uploads
        {
            using var _ = noUrls.Tenants.Use("acme");
            await Assert.ThrowsAsync<DirectUploadNotAllowedException>(() => noUrls.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "a", ClientScan = Scan }));
        }
    }

    [Fact]
    public async Task Direct_upload_lifecycle_pending_then_complete_records_the_client_attestation()
    {
        await using var env = Direct();
        env.Memory.UploadUrlBase = new Uri("https://up.test/");
        using var _ = env.Tenants.Use("acme");
        var ticket = await env.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "big.iso", ContentType = "application/x-iso", ClientScan = Scan, OwnerTags = [new("project", "p1")] });

        Assert.StartsWith("https://up.test/acme/", ticket.UploadUrl.ToString());
        Assert.Equal(env.Time.Now + TimeSpan.FromMinutes(15), ticket.ExpiresAt);
        Assert.Equal(SiloObjectStatus.PendingDirectUpload, (await env.Silo.GetAsync(ticket.ObjectId))!.Status);
        Assert.Null(await env.Silo.OpenReadAsync(ticket.ObjectId)); // not readable until completed
        await Assert.ThrowsAsync<SiloException>(() => env.Silo.CompleteDirectUploadAsync(ticket.ObjectId)); // client hasn't uploaded yet

        var bytes = Encoding.UTF8.GetBytes("uploaded straight to the provider");
        env.Memory.SimulateDirectUpload($"acme/{ticket.ObjectId:N}", bytes);
        var done = await env.Silo.CompleteDirectUploadAsync(ticket.ObjectId);

        Assert.Equal(SiloObjectStatus.Clean, done.Status);
        Assert.Equal("client:clamav/1.0", done.ScanSource);
        Assert.Equal(Scan.ScannedAt, done.ScannedAt);
        Assert.Equal(bytes.Length, done.Length);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), done.Sha256);
        Assert.Equal(bytes, await Env.ReadAll((await env.Silo.OpenReadAsync(ticket.ObjectId))!));
        await Assert.ThrowsAsync<ObjectNotFoundException>(() => env.Silo.CompleteDirectUploadAsync(ticket.ObjectId)); // single completion
    }

    [Fact]
    public async Task Oversized_direct_uploads_are_deleted_and_stale_tickets_expire()
    {
        await using var env = Direct(o => o.MaxObjectBytes = 100);
        env.Memory.UploadUrlBase = new Uri("https://up.test/");
        using var _ = env.Tenants.Use("acme");

        var big = await env.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "big", ClientScan = Scan });
        env.Memory.SimulateDirectUpload($"acme/{big.ObjectId:N}", new byte[101]);
        await Assert.ThrowsAsync<ObjectTooLargeException>(() => env.Silo.CompleteDirectUploadAsync(big.ObjectId));
        Assert.Empty(env.Memory.Keys);
        Assert.Null(await env.Silo.GetAsync(big.ObjectId));

        var stale = await env.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "stale", ClientScan = Scan });
        env.Memory.SimulateDirectUpload($"acme/{stale.ObjectId:N}", new byte[5]);
        env.Time.Now += TimeSpan.FromHours(2);
        var fresh = await env.Silo.BeginDirectUploadAsync(new DirectUploadRequest { FileName = "fresh", ClientScan = Scan });
        Assert.Equal(1, await env.Silo.ExpirePendingDirectUploadsAsync(env.Time.Now - TimeSpan.FromHours(1)));
        Assert.Null(await env.Silo.GetAsync(stale.ObjectId));
        Assert.NotNull(await env.Silo.GetAsync(fresh.ObjectId));
    }

    [Fact]
    public async Task Ownership_is_passive_tags_first_claims_later()
    {
        await using var env = new Env();
        using var _ = env.Tenants.Use("acme");
        // tagging a non-existent owner is fine: nothing is enforced at write time
        var tagged = await env.Silo.UploadAsync(Env.Req("a.txt", null, new OwnerRef("invoice", "inv-1"), new OwnerRef("invoice", "inv-1")), Env.Bytes("a"));
        var untagged = await env.Silo.UploadAsync(Env.Req("b.txt"), Env.Bytes("b"));

        Assert.Equal([new SiloOwner("invoice", "inv-1", false, null)], tagged.Owners);
        Assert.Equal([tagged.Id], (await env.Silo.FindByOwnerAsync("invoice", "inv-1")).Select(o => o.Id)); // findable via the tag, still unclaimed

        env.Time.Now += TimeSpan.FromDays(2);
        Assert.Equal(2, (await env.Silo.ListUnclaimedAsync(env.Time.Now - TimeSpan.FromDays(1))).Count(o => o.Id == tagged.Id || o.Id == untagged.Id));

        await env.Silo.ClaimAsync(tagged.Id, "invoice", "inv-1");
        await env.Silo.ClaimAsync(untagged.Id, "note", "n-7");   // claiming adds the tag if it was missing
        var claimed = (await env.Silo.GetAsync(tagged.Id))!.Owners.Single();
        Assert.True(claimed.Claimed);
        Assert.Equal(env.Time.Now, claimed.ClaimedAt);
        Assert.Empty(await env.Silo.ListUnclaimedAsync(env.Time.Now));

        var fresh = await env.Silo.UploadAsync(Env.Req("c.txt"), Env.Bytes("c"));
        Assert.Empty(await env.Silo.ListUnclaimedAsync(env.Time.Now - TimeSpan.FromDays(1))); // too new to be an orphan
        Assert.Equal([fresh.Id], (await env.Silo.ListUnclaimedAsync(env.Time.Now + TimeSpan.FromDays(1))).Select(o => o.Id));
    }

    [Fact]
    public void Schema_script_is_rls_protected()
    {
        var options = new DbContextOptionsBuilder<SiloDb>().UseNpgsql("Host=localhost;Database=x").Options;
        using var db = new SiloDb(options, new FixedTenantContext("t"));
        var script = db.GenerateSchemaScript();
        Assert.Contains("FORCE ROW LEVEL SECURITY", script);
        Assert.Contains("silo_objects", script);
        Assert.Contains("silo_object_owners", script);
    }
}
