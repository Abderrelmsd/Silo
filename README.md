# Silo

Tenant-scoped, **immutable** file storage with built-in virus scanning, on top of the storage provider of your choice.

Use it for uploads such as invoices, attachments and images, when you want every file scanned, isolated per tenant, tamper-proof once written, and independent of which cloud or disk holds the bytes.

## Install

```bash
dotnet add package Silo
```

## Quick start

```csharp
services.AddCipher(); services.AddBedrock(o => { /* ... */ });
services.AddSilo(o => o.MaxObjectBytes = 50_000_000);
services.AddSiloBedrockData();                        // object metadata in Postgres, with RLS
services.AddSiloS3(s3Client, o => o.Bucket = "files");   // or AddSiloAzureBlob / AddSiloLocalFileSystem / AddSiloRemoteServer

var obj = await silo.UploadAsync(new UploadRequest { FileName = "invoice.pdf", OwnerTags = [new("invoice", "inv-42")] }, stream);   // scanned inline
await silo.ClaimAsync(obj.Id, "invoice", "inv-42");             // ownership becomes real once claimed
await using var read = await silo.OpenReadAsync(obj.Id);        // null unless the object is clean and in this tenant
var v2 = await silo.ReplaceAsync(obj.Id, request, newStream);   // a new object id; the old one is untouched
```

## Providers

S3, Azure Blob Storage, the local file system, a remote HTTP server, plus an in-memory provider for tests. Providers only ever see opaque keys of the form `{tenant}/{objectId}`. File names and metadata live in Postgres through Bedrock (`silo_objects` and `silo_object_owners`, RLS-protected). Tenant ids must be `[A-Za-z0-9_-]` so they are safe inside storage keys.

## Immutability

Objects cannot be overwritten. Providers create-only (S3 and Azure conditional create, `FileMode.CreateNew`, or `If-None-Match: *`). A "replace" writes a new object that points back with `SupersedesId`. `PurgeAsync` exists only for erasure and retention; it deletes the metadata first and then the blob.

## Virus scanning

Every untrusted upload is spooled to a temporary file (hashing and enforcing the size limit as it streams), scanned, and only then stored. Infected uploads are rejected and never stored.

- The built-in signature scanner recognises EICAR plus your own ASCII or hex signatures. Use `AddSiloClamAv(host)` for ClamAV.
- If the scanner is down, uploads are **rejected** (`RejectWhenScannerFails`, on by default).
- `RescanAsync` re-checks stored objects and quarantines any later found infected.

## Direct-to-provider uploads

Pre-signed URL uploads bypass inline scanning, so they are off by default and only allowed with: the feature switched on, a client scan attestation naming the scanner, a provider that supports pre-signed URLs, and no at-rest encryption. The object stays `PendingDirectUpload` (unreadable) until `CompleteDirectUploadAsync` verifies its presence and size and records its SHA-256. The attestation is stored as `ScanSource = client:{scanner}`, and stale tickets can be expired.

## Encryption at rest

Optional (`EncryptAtRest`). Content is encrypted in chunks with Cipher AES-GCM; each frame's associated data ties it to the object, position and final-chunk flag, so truncation, reordering and swapping between objects fail authentication. Key rotation works because every chunk is a Cipher envelope. Pre-signed download URLs are not offered for encrypted objects.

## Ownership and integrity

Ownership is passive: owner tags given at upload are hints that nothing validates, and `ClaimAsync` confirms them. `ListUnclaimedAsync` finds orphans. A SHA-256 is recorded on write, and `VerifyIntegrityAsync` recomputes it.

## Configuration

Section `Silo`.

| Option | Default | Meaning |
|---|---|---|
| `MaxObjectBytes` | `100 MB` | Largest upload |
| `EncryptAtRest` | `false` | Encrypt content with Cipher |
| `EncryptionKeyId` | `silo-content` | Cipher key name |
| `EncryptionChunkBytes` | `64 KB` | Chunk size for encryption |
| `AllowDirectUpload` | `false` | Allow pre-signed uploads (see above) |
| `DirectUploadUrlLifetime` | `15 min` | Validity of a pre-signed upload URL |
| `RejectWhenScannerFails` | `true` | Fail closed if the scanner is unavailable |
| `AdditionalSignatures` | empty | Extra ASCII/hex signatures for the built-in scanner |

The remote-server provider adds `BaseAddress` and `BearerToken`.

## Verification status

The in-memory, local-file and stubbed remote providers are exercised by tests. The S3 and Azure providers are compile-verified only, since there was no cloud access when they were built. Metadata uses the same EF model that was tested on the InMemory provider.

## Depends on

Cipher, Bedrock.
