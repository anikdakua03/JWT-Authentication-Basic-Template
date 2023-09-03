using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Data
{
    public class AppDbContext : IdentityDbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }
        public DbSet<Team> Teams { get; set; }
        // for storing refresh token to , to match while it genrates new 
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        // for general creation of roles
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }
        private static void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                    new IdentityRole() { Name = "User", NormalizedName = "User", ConcurrencyStamp = "0" },
                    new IdentityRole() { Name = "Admin", NormalizedName = "Admin", ConcurrencyStamp = "1" },
                    new IdentityRole() { Name = "Management", NormalizedName = "Management", ConcurrencyStamp = "2" }
                );
        }
    }
}
