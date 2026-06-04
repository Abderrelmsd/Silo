using Amazon.S3;
using Amazon.S3.Model;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Sas;

namespace Silo.Providers;

public sealed class S3Options
{
    public string Bucket { get; set; } = "";
    /// <summary>Key prefix inside the bucket (e.g. "silo/").</summary>
    public string Prefix { get; set; } = "";
}

/// <summary>Amazon S3 (and S3-compatible) storage. Immutability: conditional create (<c>If-None-Match: *</c>); pre-signed URLs for direct upload/download.</summary>
public sealed class S3BlobProvider(IAmazonS3 s3, S3Options options) : IBlobProvider
{
    public string Name => "s3";
    private string K(string key) => options.Prefix + BlobKeys.Validate(key);

    public async Task PutAsync(string key, Stream content, string? contentType, CancellationToken ct = default)
    {
        var request = new PutObjectRequest { BucketName = options.Bucket, Key = K(key), InputStream = content, ContentType = contentType, IfNoneMatch = "*" };
        try { await s3.PutObjectAsync(request, ct); }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.PreconditionFailed) { throw new BlobAlreadyExistsException(key); }
    }

    public async Task<Stream> OpenReadAsync(string key, CancellationToken ct = default)
    {
        try { return (await s3.GetObjectAsync(options.Bucket, K(key), ct)).ResponseStream; }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { throw new BlobNotFoundException(key); }
    }

    public async Task<long?> GetLengthAsync(string key, CancellationToken ct = default)
    {
        try { return (await s3.GetObjectMetadataAsync(options.Bucket, K(key), ct)).ContentLength; }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { return null; }
    }

    public Task DeleteAsync(string key, CancellationToken ct = default) => s3.DeleteObjectAsync(options.Bucket, K(key), ct);

    public Task<Uri?> CreateUploadUrlAsync(string key, TimeSpan lifetime, string? contentType, CancellationToken ct = default)
        => Task.FromResult<Uri?>(new Uri(s3.GetPreSignedURL(new GetPreSignedUrlRequest { BucketName = options.Bucket, Key = K(key), Verb = HttpVerb.PUT, ContentType = contentType, Expires = DateTime.UtcNow + lifetime })));

    public Task<Uri?> CreateDownloadUrlAsync(string key, TimeSpan lifetime, CancellationToken ct = default)
        => Task.FromResult<Uri?>(new Uri(s3.GetPreSignedURL(new GetPreSignedUrlRequest { BucketName = options.Bucket, Key = K(key), Verb = HttpVerb.GET, Expires = DateTime.UtcNow + lifetime })));
}

/// <summary>Azure Blob Storage. Immutability via <c>If-None-Match: *</c>; SAS URLs need a shared-key credential on the container client.</summary>
public sealed class AzureBlobProvider(BlobContainerClient container) : IBlobProvider
{
    public string Name => "azure";

    public async Task PutAsync(string key, Stream content, string? contentType, CancellationToken ct = default)
    {
        var blob = container.GetBlobClient(BlobKeys.Validate(key));
        try
        {
            await blob.UploadAsync(content, new BlobUploadOptions
            {
                HttpHeaders = new BlobHttpHeaders { ContentType = contentType },
                Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All },
            }, ct);
        }
        catch (RequestFailedException ex) when (ex.Status is 409 or 412) { throw new BlobAlreadyExistsException(key); }
    }

    public async Task<Stream> OpenReadAsync(string key, CancellationToken ct = default)
    {
        try { return await container.GetBlobClient(BlobKeys.Validate(key)).OpenReadAsync(cancellationToken: ct); }
        catch (RequestFailedException ex) when (ex.Status == 404) { throw new BlobNotFoundException(key); }
    }

    public async Task<long?> GetLengthAsync(string key, CancellationToken ct = default)
    {
        try { return (await container.GetBlobClient(BlobKeys.Validate(key)).GetPropertiesAsync(cancellationToken: ct)).Value.ContentLength; }
        catch (RequestFailedException ex) when (ex.Status == 404) { return null; }
    }

    public Task DeleteAsync(string key, CancellationToken ct = default) => container.GetBlobClient(BlobKeys.Validate(key)).DeleteIfExistsAsync(cancellationToken: ct);

    public Task<Uri?> CreateUploadUrlAsync(string key, TimeSpan lifetime, string? contentType, CancellationToken ct = default)
        => Task.FromResult(Sas(key, lifetime, BlobSasPermissions.Create | BlobSasPermissions.Write));

    public Task<Uri?> CreateDownloadUrlAsync(string key, TimeSpan lifetime, CancellationToken ct = default)
        => Task.FromResult(Sas(key, lifetime, BlobSasPermissions.Read));

    private Uri? Sas(string key, TimeSpan lifetime, BlobSasPermissions permissions)
    {
        var blob = container.GetBlobClient(BlobKeys.Validate(key));
        return blob.CanGenerateSasUri ? blob.GenerateSasUri(permissions, DateTimeOffset.UtcNow + lifetime) : null;
    }
}
