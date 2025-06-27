using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MyVault.Shared.Models.DataModels;
using MyVault.Shared.Models.Identity;

namespace MyVault.Server.Data
{
    /// <summary>
    /// application database context class
    /// </summary>
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
            
        }

        /// <summary>
        /// Property Secrets
        /// </summary>
        /// <value></value>
        public DbSet<EmailJob>? EmailJobs { get; set; }
        /// <summary>
        /// Property Secrets
        /// </summary>
        /// <value></value>
        public DbSet<Secrets>? AppSecrets { get; set; }
        /// <summary>
        /// Property Secrets
        /// </summary>
        /// <value></value>
        public DbSet<SecretsHistory>? AppSecretsHistory { get; set; }
        /// <summary>
        /// Property AppLogs
        /// </summary>
        /// <value></value>
        public DbSet<AppLogs>? AppLogs { get; set; }
        /// <summary>
        /// property AppSettings
        /// </summary>
        /// <value></value>
        public DbSet<ApplicationSettings>? AppSettings { get; set; }
        /// <summary>
        /// property RateLimit
        /// </summary>
        /// <value></value>
        public DbSet<RateLimit>? RateLimits { get; set; }

        /// <summary>
        /// method to handle OnModelCreating
        /// </summary>
        /// <param name="builder"></param>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationSettings>()
                    .HasKey(x => new { x.Name, x.Type });

            builder.Entity<ApplicationSettings>()
                        .Property(x => x.Value);

            // seeding default settings            
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SessionTimeoutWarnAfter", Type = "GlobalSettings", Value = "5" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SessionTimeoutRedirAfter", Type = "GlobalSettings", Value = "60" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SessionCookieExpiration", Type = "GlobalSettings", Value = "10" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ShowMfaEnableBanner", Type = "GlobalSettings", Value = "true" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "AllowSelfRegister", Type = "GlobalSettings", Value = "true" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "AllowSelfPwReset", Type = "GlobalSettings", Value = "true" });

            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SmtpUsername", Type = "MailSettings", Value = "YOUR_Smtp_Username" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SmtpPassword", Type = "MailSettings", Value = "YOUR_SmtpPassword" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SmtpServer", Type = "MailSettings", Value = "YOUR_SmtpServer" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SmtpPort", Type = "MailSettings", Value = "587" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SmtpUseTls", Type = "MailSettings", Value = "true" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SmtpFromAddress", Type = "MailSettings", Value = "YOUR_From_Address" });

            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "LdapDomainController", Type = "LdapSettings", Value = "YOUR_Domaincontroller_FQDN" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "LdapDomainName", Type = "LdapSettings", Value = "YOUR_Domainname" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "LdapBaseDn", Type = "LdapSettings", Value = "DC=YOUR,DC=Domain,DC=com" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "LdapGroup", Type = "LdapSettings", Value = "YOUR_Ldap_Group" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "LdapEnabled", Type = "LdapSettings", Value = "false" });

            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ApplicationName", Type = "BrandSettings", Value = "GroupVault" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorPrimary", Type = "BrandSettings", Value = "#000000" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorSecondary", Type = "BrandSettings", Value = "#9ad936" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorInfo", Type = "BrandSettings", Value = "#1854b4" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorSuccess", Type = "BrandSettings", Value = "#9ad936" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorWarning", Type = "BrandSettings", Value = "#f5d33d" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorDanger", Type = "BrandSettings", Value = "#d62b2b" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorLightBackground", Type = "BrandSettings", Value = "#EDEDED" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorLink", Type = "BrandSettings", Value = "#9ad936" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorHeadlines", Type = "BrandSettings", Value = "#000000" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ColorTextMuted", Type = "BrandSettings", Value = "#9ca0a5" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "HeadBarBackground", Type = "BrandSettings", Value = "#000000" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "HeadBarTextColor", Type = "BrandSettings", Value = "#ffffff" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SideBarBackground", Type = "BrandSettings", Value = "#FFFFFF" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "ApplicationLogo", Type = "BrandSettings", Value = "" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "LoginBackground", Type = "BrandSettings", Value = "#000000" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "EnableCarbonStyle", Type = "BrandSettings", Value = "true" });

            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SendNotifOnObjectUpdate", Type = "NotificationSettings", Value = "false" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SendNotifOnObjectCreation", Type = "NotificationSettings", Value = "false" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SendNotifOnObjectDeletion", Type = "NotificationSettings", Value = "false" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SendNotifOnUserSelfRegister", Type = "NotificationSettings", Value = "false" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "SendWelcomeMailOnUserCreation", Type = "NotificationSettings", Value = "false" });
            builder.Entity<ApplicationSettings>().HasData(new ApplicationSettings { Name = "NotificationReceiver", Type = "NotificationSettings", Value = "yourmailaddres@yourdomain.com" });

            

             //Seeding roles to AspNetRoles table
            builder.Entity<AppRole>().HasData(new AppRole { Id = "dffc6dd5-b145-41e9-a861-c87ff673e9ca", Name = "Admin", NormalizedName = "ADMIN".ToUpper() });
            builder.Entity<AppRole>().HasData(new AppRole { Id = "f8a527ac-d7f6-4d9d-aca6-46b2261b042b", Name = "User", NormalizedName = "USER".ToUpper() });


            //a hasher to hash the password before seeding the user to the db
            var hasher = new PasswordHasher<AppUser>();

            //Seeding the Admin User to AspNetUsers table
            builder.Entity<AppUser>().HasData(
                new AppUser
                {
                    Id = "6fbfb682-568c-4f5b-a298-85937ca4f7f3", // primary key
                    UserName = "super.admin",
                    NormalizedUserName = "SUPER.ADMIN",
                    PasswordHash = hasher.HashPassword(null!, "Test1000!"),
                    Email = "super.admin@local.app",
                    NormalizedEmail = "SUPER.ADMIN@LOCAL.APP",
                    EmailConfirmed = true,
                    FirstName = "Super",
                    LastName = "Admin",
                    IsMfaForce = false,
                    IsLdapLogin = false,
                    IsEnabled = true,
                    RolesCombined = "Admin",
                    PhoneNumber = "111"
                }
            );

            //Seeding the relation between our user and role to AspNetUserRoles table
            builder.Entity<IdentityUserRole<string>>().HasData(
                new IdentityUserRole<string>
                {
                    RoleId = "dffc6dd5-b145-41e9-a861-c87ff673e9ca",
                    UserId = "6fbfb682-568c-4f5b-a298-85937ca4f7f3"
                }
            );
        }
    }
}
