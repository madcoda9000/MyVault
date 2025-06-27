using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using MyVault.Server.Data;
using MyVault.Shared.Models.DataModels;

namespace MyVault.Server.Middleware
{
    /// <summary>
    /// dblogger class
    /// </summary>
    public class DbLogger : ILogger
    {
        /// <summary>
        /// property categoryName
        /// </summary>
        public readonly string categoryName;
        /// <summary>
        /// property dbcontext
        /// </summary>
        private readonly IDbContextFactory<AppDbContext> _contextFactory;


        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="categoryName"></param>
        /// <param name="contextFactory"></param>
        public DbLogger(string categoryName, IDbContextFactory<AppDbContext> contextFactory)
        {
            this.categoryName = categoryName;
            this._contextFactory = contextFactory;
        }

        /// <summary>
        /// IsEnable method
        /// </summary>
        /// <param name="logLevel"></param>
        /// <returns></returns>
        public bool IsEnabled(LogLevel logLevel)
        {
            // Implement the desired logic to determine if the specified log level is enabled or not
            // Return true if enabled, false otherwise
            return true;
        }

        /// <summary>
        /// beginscopr method
        /// </summary>
        /// <param name="state"></param>
        /// <typeparam name="TState"></typeparam>
        /// <returns></returns>
#pragma warning disable CS8633
        public IDisposable BeginScope<TState>(TState state)
        {
            // Implement the logic to begin a new scope for the logger if needed
            // Return an IDisposable object that represents the scope (e.g., a new class instance)
            // If not using scopes, you can simply return null
            return null!;
        }
#pragma warning restore CS8633

        /// <summary>
        /// method to insert log entry
        /// </summary>
        /// <param name="logLevel"></param>
        /// <param name="eventId"></param>
        /// <param name="state"></param>
        /// <param name="exception"></param>
        /// <param name="formatter"></param>
        /// <typeparam name="TState"></typeparam>
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            string message = formatter(state, exception);
            bool shouldLog = true;

            // Filter unwanted categories or paths
            if (categoryName.ToLower().Contains("microsoft.hosting.lifetime")) shouldLog = false;
            if (categoryName.ToLower().Contains("microsoft.entityframeworkcore")) shouldLog = false;
            if (message.Contains(" /api/Authenticate/verifyMfaAuth")) shouldLog = false;

            if (!shouldLog) return;

            var logEntry = new AppLogs
            {
                Timestamp = DateTime.Now,
                LogLevel = logLevel,
                Category = categoryName,
                Exception = exception?.ToString() ?? string.Empty
            };

            if (!string.IsNullOrEmpty(message) && message.Contains(Environment.NewLine))
            {
                var index = message.IndexOf(Environment.NewLine);
                logEntry.Subject = message.Substring(0, index);
                logEntry.Data = message.Substring(index + 2);
            }
            else
            {
                logEntry.Subject = message;
                logEntry.Data = "=== NO ADDITIONAL DATA ===";
            }

            try
            {
                using var context = _contextFactory.CreateDbContext();
                context.AppLogs!.Add(logEntry);
                context.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DbLogger error: {ex.Message}");
            }
        }
    }
}