using Amazon.S3;
using Azure.Storage.Blobs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Bedrock;
using Silo.Data;
using Silo.Providers;

namespace Silo;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="ISilo"/> with the built-in signature scanner. Also register exactly one provider
    /// (<c>AddSiloLocalFileSystem</c>, <c>AddSiloS3</c>, <c>AddSiloAzureBlob</c>, <c>AddSiloRemoteServer</c>) and a metadata store (<c>AddSiloBedrockData</c>). Requires Cipher and Bedrock.
    /// </summary>
    public static IServiceCollection AddSilo(this IServiceCollection services, Action<SiloOptions>? configure = null)
    {
        var o = services.AddOptions<SiloOptions>();
        if (configure is not null) o.Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IVirusScanner>(sp => new BasicSignatureScanner(sp.GetRequiredService<IOptions<SiloOptions>>().Value.AdditionalSignatures));
        services.TryAddSingleton<ISilo, SiloService>();
        return services;
    }

    public static IServiceCollection AddSiloBedrockData(this IServiceCollection services)
    {
        services.AddBedrockDbContext<SiloDb>();
        services.TryAddSingleton<ISiloDbFactory, BedrockSiloDbFactory>();
        return services;
    }

    public static IServiceCollection AddSiloInMemory(this IServiceCollection services) => services.ReplaceProvider(new InMemoryBlobProvider());
    public static IServiceCollection AddSiloLocalFileSystem(this IServiceCollection services, string rootPath) => services.ReplaceProvider(new LocalFileSystemBlobProvider(rootPath));

    public static IServiceCollection AddSiloRemoteServer(this IServiceCollection services, Action<RemoteServerOptions> configure, HttpMessageHandler? handler = null)
    {
        var o = new RemoteServerOptions();
        configure(o);
        return services.ReplaceProvider(new RemoteServerBlobProvider(handler is null ? new HttpClient() : new HttpClient(handler), o));
    }

    /// <summary>Uses the given S3 client (credentials/region/endpoint are yours to configure — works with S3-compatible stores too).</summary>
    public static IServiceCollection AddSiloS3(this IServiceCollection services, IAmazonS3 client, Action<S3Options> configure)
    {
        var o = new S3Options();
        configure(o);
        return services.ReplaceProvider(new S3BlobProvider(client, o));
    }

    /// <summary>Uses the given container client. Construct it with a shared-key credential to enable SAS direct-upload URLs.</summary>
    public static IServiceCollection AddSiloAzureBlob(this IServiceCollection services, BlobContainerClient container) => services.ReplaceProvider(new AzureBlobProvider(container));

    public static IServiceCollection AddSiloClamAv(this IServiceCollection services, string host, int port = 3310)
    {
        services.RemoveAll<IVirusScanner>();
        return services.AddSingleton<IVirusScanner>(ClamAvScanner.Tcp(host, port));
    }

    private static IServiceCollection ReplaceProvider(this IServiceCollection services, IBlobProvider provider)
    {
        services.RemoveAll<IBlobProvider>();
        return services.AddSingleton(provider);
    }
}
