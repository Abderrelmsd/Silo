using System.Buffers.Binary;
using System.Text;
using Cipher;
using Cipher.Encryption;

namespace Silo;

/// <summary>
/// Chunked authenticated encryption for blobs, built on Cipher's AES-GCM (key versions are recorded per chunk, so key rotation is safe).
/// Layout: <c>"QSILO1"</c> then frames <c>[int32 length][Cipher envelope]</c>. AAD per chunk = objectId ‖ chunk index ‖ final flag, so chunks
/// can't be reordered, swapped between objects, or dropped from the end (truncation fails authentication).
/// </summary>
internal static class ChunkedEncryption
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("QSILO1");

    public static async Task EncryptAsync(IEncryptionService enc, string keyId, Stream input, Stream output, Guid objectId, int chunkBytes, CancellationToken ct)
    {
        await output.WriteAsync(Magic, ct);
        var current = new byte[chunkBytes];
        var next = new byte[chunkBytes];
        var currentLen = await ReadFullAsync(input, current, ct);
        var index = 0;
        while (true)
        {
            var nextLen = currentLen == chunkBytes ? await ReadFullAsync(input, next, ct) : 0;
            var isFinal = nextLen == 0;
            var envelope = await enc.EncryptAsync(keyId, current.AsMemory(0, currentLen), Aad(objectId, index, isFinal), ct);
            var len = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(len, envelope.Length);
            await output.WriteAsync(len, ct);
            await output.WriteAsync(envelope, ct);
            if (isFinal) return;
            (current, next) = (next, current);
            currentLen = nextLen;
            index++;
        }
    }

    public static Stream Decrypt(IEncryptionService enc, string keyId, Stream input, Guid objectId) => new DecryptingStream(enc, keyId, input, objectId);

    internal static byte[] Aad(Guid objectId, int index, bool final)
    {
        var aad = new byte[16 + 4 + 1];
        objectId.TryWriteBytes(aad);
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(16), index);
        aad[20] = final ? (byte)1 : (byte)0;
        return aad;
    }

    private static async Task<int> ReadFullAsync(Stream s, byte[] buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await s.ReadAsync(buffer.AsMemory(total), ct);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    private sealed class DecryptingStream(IEncryptionService enc, string keyId, Stream input, Guid objectId) : Stream
    {
        private byte[] _plain = [];
        private int _pos;
        private int _index;
        private bool _started, _done;
        private byte[]? _pendingLen; // length header of the next frame, pre-read to learn whether the current frame is final

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) input.Dispose(); base.Dispose(disposing); }

        public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken ct = default)
        {
            while (_pos >= _plain.Length)
            {
                if (_done) return 0;
                await LoadNextChunkAsync(ct);
            }
            var n = Math.Min(destination.Length, _plain.Length - _pos);
            _plain.AsMemory(_pos, n).CopyTo(destination);
            _pos += n;
            return n;
        }

        private async Task LoadNextChunkAsync(CancellationToken ct)
        {
            if (!_started)
            {
                var magic = new byte[Magic.Length];
                if (await ReadExactOrEofAsync(magic, ct) != magic.Length || !magic.AsSpan().SequenceEqual(Magic))
                    throw new CipherDecryptionException("Not a Silo-encrypted object.");
                _started = true;
                _pendingLen = new byte[4];
                if (await ReadExactOrEofAsync(_pendingLen, ct) != 4) throw new CipherDecryptionException("Encrypted object is truncated.");
            }

            var frameLen = BinaryPrimitives.ReadInt32BigEndian(_pendingLen);
            if (frameLen <= 0 || frameLen > 16 * 1024 * 1024) throw new CipherDecryptionException("Corrupt chunk header.");
            var envelope = new byte[frameLen];
            if (await ReadExactOrEofAsync(envelope, ct) != frameLen) throw new CipherDecryptionException("Encrypted object is truncated.");

            var lenBuf = new byte[4];
            var got = await ReadExactOrEofAsync(lenBuf, ct);
            var isFinal = got == 0;
            if (got is not (0 or 4)) throw new CipherDecryptionException("Encrypted object is truncated.");

            _plain = await enc.DecryptAsync(keyId, envelope, Aad(objectId, _index++, isFinal), ct);
            _pos = 0;
            _pendingLen = lenBuf;
            _done = isFinal;
        }

        private async Task<int> ReadExactOrEofAsync(byte[] buffer, CancellationToken ct)
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var n = await input.ReadAsync(buffer.AsMemory(total), ct);
                if (n == 0) break;
                total += n;
            }
            return total;
        }
    }
}
