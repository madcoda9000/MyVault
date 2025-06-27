using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// audit object model
    /// </summary>
    public class AuditEntryModel
    {
        /// <summary>
        /// level property
        /// </summary>
        /// <value></value>
        public int level {get;set;} = 2;
        /// <summary>
        /// source property
        /// </summary>
        /// <value></value>
        public string source {get;set;} = string.Empty;
        /// <summary>
        /// message property
        /// </summary>
        /// <value></value>
        public string message {get;set;} = string.Empty;
    }
}