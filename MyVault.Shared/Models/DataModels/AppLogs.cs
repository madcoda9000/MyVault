using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.DataModels
{
    /// <summary>
    /// class to define ann Log object
    /// </summary>
    public class AppLogs
    {
        /// <summary>
        /// id property
        /// </summary>
        /// <value></value>
        public int Id { get; set; }
        /// <summary>
        /// timestamp property
        /// </summary>
        /// <value></value>
        public DateTime Timestamp { get; set; }
        /// <summary>
        /// log level property
        /// </summary>
        /// <value></value>
        public LogLevel LogLevel { get; set; }
        /// <summary>
        /// category property
        /// </summary>
        /// <value></value>
        public string Category { get; set; } = string.Empty;
        /// <summary>
        /// subject property
        /// </summary>
        /// <value></value>
        public string Subject {get;set;} = string.Empty;
        /// <summary>
        /// data property
        /// </summary>
        /// <value></value>
        public string Data { get; set; } = string.Empty;
        /// <summary>
        /// exception property
        /// </summary>
        /// <value></value>
        public string Exception { get; set; }  = string.Empty;
    }
}