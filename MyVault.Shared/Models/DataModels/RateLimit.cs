using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

namespace MyVault.Shared.Models.DataModels
{
    /// <summary>
    /// model definition for rate limit entries
    /// </summary>
    [Table("RateLimit")]
    public class RateLimit
    {
        /// <summary>
        /// primary key
        /// </summary>
        [Key]
        public Guid id {get; set;}
        /// <summary>
        /// the request path 
        /// </summary>//  
        public string RequestPath {get;set;} = string.Empty;
        /// <summary>
        /// retry after
        /// </summary>
        public string RetryAfter {get;set;} = string.Empty;
        /// <summary>
        /// the http status code
        /// </summary>
        public string StatusCode {get;set;} = string.Empty;
        /// <summary>
        /// client ip
        /// </summary>
        /// <value></value>
        public string ClientIP {get;set;} = string.Empty;
    }
}