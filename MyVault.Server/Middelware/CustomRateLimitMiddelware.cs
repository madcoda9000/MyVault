using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNetCoreRateLimit;
using Microsoft.Extensions.Options;
using System.Text.Json;
using MyVault.Server.Data;
using MyVault.Shared.Models.DataModels;

namespace MyVault.Server.Middleware
{
    /// <summary>
    /// Class for rate limiter
    /// </summary>
    public class CustomClientRateLimitMiddleware : ClientRateLimitMiddleware
    {
        /// <summary>
        /// sql server db context
        /// </summary>
        private readonly IServiceScopeFactory _serviceScopeFactory;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="next"></param>
        /// <param name="processingStrategy"></param>
        /// <param name="options"></param>
        /// <param name="policyStore"></param>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        /// <param name="serviceScopeFactory"></param> 
        /// <returns></returns>
        public CustomClientRateLimitMiddleware(RequestDelegate next,
            IProcessingStrategy processingStrategy,
            IOptions<ClientRateLimitOptions> options,
            IClientPolicyStore policyStore,
            IRateLimitConfiguration config,
            ILogger<ClientRateLimitMiddleware> logger,
            IServiceScopeFactory serviceScopeFactory) : base(next, processingStrategy, options, policyStore, config, logger)
        {
            this._serviceScopeFactory = serviceScopeFactory;
        }

        /// <summary>
        /// task to return quata exceeded response
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="rule"></param>
        /// <param name="retryAfter"></param>
        /// <returns></returns>
        public override Task ReturnQuotaExceededResponse(HttpContext httpContext, RateLimitRule rule, string retryAfter)
        {
            var result = JsonSerializer.Serialize("API calls quota exceeded!");
            if (httpContext != null)
            {
                var clIp = httpContext.Connection.RemoteIpAddress!.ToString();
                httpContext.Response.Headers["Retry-After"] = retryAfter;
                httpContext.Response.StatusCode = 429;
                httpContext.Response.ContentType = "application/json";
                WriteQuotaExceededResponseMetadata(httpContext.Request.Path, retryAfter, clIp);
                return httpContext.Response.WriteAsync(result);
            }  else {
                return Task.FromException(new Exception("HttpContext is Null!"));
            }          
        }

        /// <summary>
        /// procedure to write exceeded response Metadata to database
        /// </summary>
        /// <param name="requestPath"></param>
        /// <param name="retryAfter"></param>
        /// <param name="statusCode"></param>
        /// <param name="clientIP"></param>
        private void WriteQuotaExceededResponseMetadata(string? requestPath, string? retryAfter, string clientIP, int statusCode = 429)
        {
            using (var scope = _serviceScopeFactory.CreateScope())
            {
                if (scope != null && scope.ServiceProvider != null && requestPath != null && retryAfter != null)
                {
                    AppDbContext _context = scope.ServiceProvider.GetService<AppDbContext>() ?? throw new Exception("Unable to create scoped AppDbContext.");
                    RateLimit rl = new RateLimit();
                    rl.id = Guid.NewGuid();
                    rl.RequestPath = requestPath;
                    rl.RetryAfter = retryAfter;
                    rl.StatusCode = statusCode.ToString();
                    rl.ClientIP = clientIP;

                    _context.RateLimits!.Add(rl);
                    _context.SaveChanges();
                }
            }
        }
    }
}