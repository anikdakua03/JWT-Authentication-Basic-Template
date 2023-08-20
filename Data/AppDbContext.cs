using JWTAuth.Models;
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
    }
}
