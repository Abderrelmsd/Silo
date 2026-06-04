namespace Silo;

public sealed class SiloOptions
{
    public const string SectionName = "Silo";

    public long MaxObjectBytes { get; set; } = 100L * 1024 * 1024;

    /// <summary>Encrypt content at rest with Cipher (chunked AES-GCM). Incompatible with direct-to-provider uploads.</summary>
    public bool EncryptAtRest { get; set; }
    public string EncryptionKeyId { get; set; } = "silo-content";
    public int EncryptionChunkBytes { get; set; } = 64 * 1024;

    /// <summary>Allow clients to upload straight to the provider (bypassing inline scanning) — only with a <see cref="ClientScanAttestation"/>.</summary>
    public bool AllowDirectUpload { get; set; }
    public TimeSpan DirectUploadUrlLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>If the scanner itself fails: reject the upload (default, fail closed) or store unscanned.</summary>
    public bool RejectWhenScannerFails { get; set; } = true;

    /// <summary>Extra byte signatures for the built-in scanner (name → ASCII/hex pattern via <see cref="BasicSignatureScanner"/>).</summary>
    public Dictionary<string, string> AdditionalSignatures { get; set; } = [];
}
