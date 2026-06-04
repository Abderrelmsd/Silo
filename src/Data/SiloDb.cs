using Microsoft.EntityFrameworkCore;
using Bedrock;

namespace Silo.Data;

public class SiloObjectRow : ITenantScoped
{
    public Guid Id { get; set; }
    public string TenantId { get; set; } = "";
    public string FileName { get; set; } = "";
    public string ContentType { get; set; } = "";
    public long Length { get; set; }
    public string Sha256 { get; set; } = "";
    public SiloObjectStatus Status { get; set; }
    public string ScanSource { get; set; } = "";
    public DateTimeOffset? ScannedAt { get; set; }
    public bool Encrypted { get; set; }
    public Guid? SupersedesId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string? CreatedBy { get; set; }
}

public class SiloOwnerRow : ITenantScoped
{
    public Guid ObjectId { get; set; }
    public string OwnerType { get; set; } = "";
    public string OwnerId { get; set; } = "";
    public string TenantId { get; set; } = "";
    public bool Claimed { get; set; }
    public DateTimeOffset? ClaimedAt { get; set; }
}

public sealed class SiloDb(DbContextOptions<SiloDb> options, ITenantContext tenant) : BedrockDbContext(options, tenant)
{
    public DbSet<SiloObjectRow> Objects => Set<SiloObjectRow>();
    public DbSet<SiloOwnerRow> Owners => Set<SiloOwnerRow>();

    protected override void OnModelCreating(ModelBuilder mb)
    {
        mb.Entity<SiloObjectRow>(e =>
        {
            e.ToTable("silo_objects"); e.HasKey(x => x.Id);
            e.Property(x => x.FileName).HasMaxLength(255); e.Property(x => x.ContentType).HasMaxLength(200);
            e.Property(x => x.Sha256).HasMaxLength(64); e.Property(x => x.ScanSource).HasMaxLength(200);
            e.HasIndex(x => new { x.TenantId, x.CreatedAt });
        });
        mb.Entity<SiloOwnerRow>(e =>
        {
            e.ToTable("silo_object_owners"); e.HasKey(x => new { x.ObjectId, x.OwnerType, x.OwnerId });
            e.Property(x => x.OwnerType).HasMaxLength(100); e.Property(x => x.OwnerId).HasMaxLength(200);
            e.HasIndex(x => new { x.TenantId, x.OwnerType, x.OwnerId });
            e.HasOne<SiloObjectRow>().WithMany().HasForeignKey(x => x.ObjectId).OnDelete(DeleteBehavior.Cascade);
        });
        base.OnModelCreating(mb);
    }

    public string GenerateSchemaScript() => this.GenerateScript();
}

public interface ISiloDbFactory
{
    SiloDb CreateTenant();
}

internal sealed class BedrockSiloDbFactory(IBedrockDbContextFactory<SiloDb> inner) : ISiloDbFactory
{
    public SiloDb CreateTenant() => inner.CreateTenant();
}
