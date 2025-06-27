using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using MyVault.Server.Data;

namespace MyVault.Server.Middleware
{
    /// <summary>
    /// logging provider model
    /// </summary>
    public class DbLoggingProvider : ILoggerProvider
    {
        /// <summary>
        /// dbcontext property
        /// </summary>
        private readonly IDbContextFactory<AppDbContext> _contextFactory;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="contextFactory"></param>
        public DbLoggingProvider(IDbContextFactory<AppDbContext> contextFactory)
        {
            _contextFactory = contextFactory;
        }

        /// <summary>
        /// create logger instance
        /// </summary>
        /// <param name="categoryName"></param>
        /// <returns></returns>
        public ILogger CreateLogger(string categoryName)
        {
            // Create and return an instance of your MySQL logger
            return new DbLogger(categoryName, _contextFactory);
        }

        /// <summary>
        /// dispose logger instance
        /// </summary>
        public void Dispose()
        {
            // Cleanup resources if needed
        }
    }
}