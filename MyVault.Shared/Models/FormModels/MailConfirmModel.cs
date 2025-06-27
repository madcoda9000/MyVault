using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// mail confirm model
    /// </summary>
    public class MailConfirmModel
    {
        /// <summary>
        /// url property
        /// </summary>
        /// <value></value>
        public string url {get;set;} = string.Empty;
        /// <summary>
        /// name property
        /// </summary>
        /// <value></value>
        public string name {get;set;} = string.Empty;
    }
}