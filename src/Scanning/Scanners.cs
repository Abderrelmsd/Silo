using System.Buffers.Binary;
using System.Text;

namespace Silo;

public abstract record ScanResult
{
    public sealed record Clean(string Engine) : ScanResult;
    public sealed record Infected(string Engine, string Signature) : ScanResult;
}

/// <summary>Scans an upload. Throw (any exception) when the scan itself can't be completed; Silo then fails closed (configurable).</summary>
public interface IVirusScanner
{
    string Name { get; }
    /// <summary>The stream is seekable and positioned at 0; leave it wherever you like (Silo rewinds).</summary>
    Task<ScanResult> ScanAsync(Stream content, CancellationToken cancellationToken = default);
}

/// <summary>
/// Built-in scanner: byte-signature matching over the stream (constant memory). Ships the EICAR test signature; add your own via
/// <see cref="SiloOptions.AdditionalSignatures"/> (values are ASCII, or <c>hex:</c>-prefixed hex). Use <see cref="ClamAvScanner"/> for full AV coverage.
/// </summary>
public sealed class BasicSignatureScanner : IVirusScanner
{
    public const string EicarSignature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private readonly List<(string Name, byte[] Pattern)> _signatures = [("Eicar-Test-Signature", Encoding.ASCII.GetBytes(EicarSignature))];

    public BasicSignatureScanner(IEnumerable<KeyValuePair<string, string>>? additional = null)
    {
        foreach (var (name, pattern) in additional ?? [])
            _signatures.Add((name, pattern.StartsWith("hex:", StringComparison.OrdinalIgnoreCase) ? Convert.FromHexString(pattern[4..]) : Encoding.ASCII.GetBytes(pattern)));
        if (_signatures.Any(s => s.Pattern.Length == 0)) throw new ArgumentException("Empty signature.");
    }

    public string Name => "silo-signatures";

    public async Task<ScanResult> ScanAsync(Stream content, CancellationToken ct = default)
    {
        var overlap = _signatures.Max(s => s.Pattern.Length) - 1;
        var buffer = new byte[64 * 1024 + overlap];
        var carried = 0;
        int read;
        while ((read = await content.ReadAsync(buffer.AsMemory(carried, buffer.Length - carried), ct)) > 0)
        {
            var total = carried + read;
            var window = buffer.AsSpan(0, total);
            foreach (var (name, pattern) in _signatures)
                if (window.IndexOf(pattern) >= 0) return new ScanResult.Infected(Name, name);

            carried = Math.Min(overlap, total);
            window[^carried..].CopyTo(buffer); // keep the tail so a signature spanning two reads is still found
        }
        return new ScanResult.Clean(Name);
    }
}

/// <summary>ClamAV over the clamd <c>INSTREAM</c> protocol. The connection factory is injectable (default: TCP to host:port).</summary>
public sealed class ClamAvScanner(Func<CancellationToken, Task<Stream>> connect, int chunkBytes = 32 * 1024) : IVirusScanner
{
    public string Name => "clamav";

    public static ClamAvScanner Tcp(string host, int port = 3310)
        => new(async ct =>
        {
            var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(host, port, ct);
            return client.GetStream();
        });

    public async Task<ScanResult> ScanAsync(Stream content, CancellationToken ct = default)
    {
        await using var conn = await connect(ct);
        await conn.WriteAsync(Encoding.ASCII.GetBytes("zINSTREAM\0"), ct);

        var buffer = new byte[chunkBytes];
        var lenBytes = new byte[4];
        int read;
        while ((read = await content.ReadAsync(buffer, ct)) > 0)
        {
            BinaryPrimitives.WriteUInt32BigEndian(lenBytes, (uint)read);
            await conn.WriteAsync(lenBytes, ct);
            await conn.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        await conn.WriteAsync(new byte[4], ct); // zero-length chunk ends the stream
        await conn.FlushAsync(ct);

        using var response = new MemoryStream();
        var b = new byte[256];
        int n;
        while ((n = await conn.ReadAsync(b, ct)) > 0)
        {
            response.Write(b, 0, n);
            if (b.AsSpan(0, n).Contains((byte)0)) break;
        }
        return Parse(Encoding.ASCII.GetString(response.ToArray()).TrimEnd('\0', '\n', ' '));
    }

    internal static ScanResult Parse(string reply)
    {
        // "stream: OK" | "stream: Eicar-Test-Signature FOUND" | "INSTREAM size limit exceeded. ERROR"
        if (reply.EndsWith("OK", StringComparison.Ordinal)) return new ScanResult.Clean("clamav");
        if (reply.EndsWith("FOUND", StringComparison.Ordinal))
        {
            var sig = reply.Split(':', 2).Last().Trim();
            return new ScanResult.Infected("clamav", sig[..^"FOUND".Length].Trim());
        }
        throw new ScanUnavailableException($"clamd replied: {reply}");
    }
}
