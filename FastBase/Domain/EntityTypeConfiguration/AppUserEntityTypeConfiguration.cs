using Domain.Admin;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.EntityTypeConfiguration
{
    public class AppUserEntityTypeConfiguration : IEntityTypeConfiguration<AppUser>
    {
        public void Configure(EntityTypeBuilder<AppUser> builder)
        {
            builder.HasMany(x => x.RefreshTokens)
                .WithOne(x => x.AppUser)
                .HasForeignKey(x => x.AppUserId)
                .OnDelete(DeleteBehavior.Cascade);

            //builder.HasMany(x => x.Roles)
            //    .WithOne(x => x.ModifiedByUser)
            //    .HasForeignKey(x => x.ModifiedByUserId);

            //builder.HasMany(x => x.AddedByRoles)
            //    .WithOne(x => x.AddedByUser)
            //    .HasForeignKey(x => x.AddedbyUserId);

            
        }
    }
}
