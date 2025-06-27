using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MyVault.Server.BackGroundTasks;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Server.Middleware;
using MyVault.Shared.Models.Identity;
using MyVault.Server.Services;
using RazorLight;
using Swashbuckle.AspNetCore.Filters;
using System.IO.Compression;
using System.Reflection;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager configuration = builder.Configuration;

// 1. Entity Framework / DB
string connStr = Environment.GetEnvironmentVariable("G_CONNECTIONSTRING") ?? configuration.GetConnectionString("MySql")!;
//builder.Services.AddDbContext<AppDbContext>(options => options.UseMySql(connStr, ServerVersion.AutoDetect(connStr)));
builder.Services.AddDbContextFactory<AppDbContext>(options =>
    options.UseMySql(connStr, ServerVersion.AutoDetect(connStr)));

// 2. Logging inkl. DB Logging Provider
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// 3. Identity & Auth
builder.Services.AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

string validAudience = Environment.GetEnvironmentVariable("G_VALIDAUDIENCE") ?? configuration["JWT:ValidAudience"]!;
string validIssuer = Environment.GetEnvironmentVariable("G_VALIDISSUER") ?? configuration["JWT:ValidIssuer"]!;
string jwtSecret = Environment.GetEnvironmentVariable("G_SECRET") ?? configuration["JWT:Secret"]!;

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.Zero,
        ValidAudience = validAudience,
        ValidIssuer = validIssuer,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
    };

    // WICHTIG: JWT aus Cookie lesen!
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // Hole accessToken aus Cookie statt aus Header
            var accessToken = context.Request.Cookies["accessToken"];
            if (!string.IsNullOrEmpty(accessToken))
            {
                context.Token = accessToken;
            }
            return Task.CompletedTask;
        }
    };
});

// 4. Eigene Services, HostedServices, RazorLight, Email, etc.
builder.Services.AddScoped<ISettingsService, SettingsService>();
builder.Services.AddScoped<IEncryptionServices, EncryptionServices>();
builder.Services.AddScoped<EmailHelper>();
builder.Services.AddHostedService<EmailTasks>();
builder.Services.AddSingleton<IEmailTasks, EmailTasks>(serviceProvider =>
{
    return EmailTasks.Instance ?? throw new Exception("Cannot get instance of EmailTasks service.");
});
builder.Services.AddSingleton<IHostedServiceStatus, HostedServiceStatus>();
builder.Services.AddSingleton<IRazorLightEngine>(provider => new RazorLightEngineBuilder()
    .UseFileSystemProject(Directory.GetCurrentDirectory() + "/MailTemplates")
    .UseMemoryCachingProvider()
    .Build());
builder.Services.AddScoped<IEmailSendService, EmailSendService>();

// 5. CORS, Controllers, Swagger/OpenAPI
builder.Services.AddCors();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "GroupVault API",
        Version = "v1",
        Description = "Backend API for GroupVault Webclient.",
        Contact = new OpenApiContact
        {
            Name = "GroupVault",
            Email = "madcoda9000@users.noreply.github.com",
            Url = new Uri("https://github.com/madcoda9000/GroupVault"),
        },
        License = new OpenApiLicense
        {
            Name = "License: MIT",
            Url = new Uri("https://de.wikipedia.org/wiki/MIT-Lizenz"),
        }
    });
    option.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Standard Authorization header using the Bearer scheme. Example: \"bearer {token}\"",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.OperationFilter<SecurityRequirementsOperationFilter>();
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Bearer"
                }
            },
            new string[]{}
        }
    });
    option.OperationFilter<AppendAuthorizeToSummaryOperationFilter>();
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    option.IncludeXmlComments(xmlPath);
});

// 6. ResponseCompression
builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
});
builder.Services.Configure<BrotliCompressionProviderOptions>(options =>
{
    options.Level = CompressionLevel.Fastest;
});
builder.Services.Configure<GzipCompressionProviderOptions>(options =>
{
    options.Level = CompressionLevel.Optimal;
});

// 7. Rate Limiting (IP/Client)
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddInMemoryRateLimiting();

List<string> EndpointWhiteList = new()
{
    "get:/user/ping"
};
string ratelimiterEnabled = Environment.GetEnvironmentVariable("G_RATELIMIENABLED") ?? configuration["AppSettings:RateLimitEnabled"]!;
string rateLimitTimespan = Environment.GetEnvironmentVariable("G_RATELIMITTIMESPAN") ?? configuration["AppSettings:RateLimitTimeSpan"]!;
string rateLimitRequestsInTimespan = Environment.GetEnvironmentVariable("G_RATELIMITREQUESTSINTIMESPAN") ?? configuration["AppSettings:RateLimitRequestsInTimespan"]!;

builder.Services.Configure<ClientRateLimitOptions>(options =>
{
    options.EnableEndpointRateLimiting = Convert.ToBoolean(ratelimiterEnabled);
    options.StackBlockedRequests = false;
    options.HttpStatusCode = 429;
    options.ClientIdHeader = "Client-Id";
    options.EndpointWhitelist = EndpointWhiteList;
    options.GeneralRules = new List<RateLimitRule>
        {
            new RateLimitRule
            {
                Endpoint = "*",
                Period = rateLimitTimespan,
                Limit = Convert.ToInt32(rateLimitRequestsInTimespan)
            }
        };
});



builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

builder.WebHost.UseStaticWebAssets();

var app = builder.Build();

// Hole LoggerFactory & DbContextFactory
var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
var dbContextFactory = app.Services.GetRequiredService<IDbContextFactory<AppDbContext>>();

// F�ge benutzerdefinierten Logger hinzu
loggerFactory.AddProvider(new DbLoggingProvider(dbContextFactory));

// Optional: Initial Migration
string migEnabled = Environment.GetEnvironmentVariable("G_MIGRAATEONSTARTUP") ?? configuration["AppSettings:MigrateOnStartup"] ?? "true";
if (migEnabled == "true")
{
    using (var scope = app.Services.CreateScope())
    {
        var dataContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await dataContext.GetInfrastructure().GetService<IMigrator>()!.MigrateAsync("Initial_MySql");
    }
}

// Compression
app.UseResponseCompression();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();;
    app.UseStaticFiles();
}

// CORS
string validOrigins = Environment.GetEnvironmentVariable("G_VALID_ORIGINS") ?? configuration["JWT:ValidOrigins"]!;
app.UseCors(policy =>
{
    if (!String.IsNullOrEmpty(validOrigins))
    {
        var ValidOrigins = validOrigins
        .Split(';', StringSplitOptions.RemoveEmptyEntries)
        .Select(o => o.Trim())
        .ToArray();

        if (ValidOrigins.Length == 0)
        {
            // Optional: Logging/Exception
            throw new InvalidOperationException("No valid origins configured for CORS!");
        }

        policy.WithOrigins(ValidOrigins)
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    }
});

// Rate Limiting Middleware
app.UseMiddleware<CustomClientRateLimitMiddleware>();

app.UseHttpsRedirection();

// content security policy
app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none';";
    await next();
});


app.UseAuthorization();

app.MapControllers();

app.Run();
