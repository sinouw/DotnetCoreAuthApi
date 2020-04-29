using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Models
{
    public class CrayonContext : IdentityDbContext
    {
        public CrayonContext(DbContextOptions options) : base(options)
        {

        }

        // Creating Roles for the application
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<IdentityRole>().HasData(
                    new { Id = "1", Name = "GlobalAdmin", NormalizedName = "GLOBALADMIN" },
                    new { Id = "2", Name = "Admin", NormalizedName = "ADMIN" }
                );
        }

        public DbSet<ApplicationUser> ApplicationUsers { get; set; }
    }
}
