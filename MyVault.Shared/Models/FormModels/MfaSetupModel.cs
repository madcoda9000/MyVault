using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// mfa setup model
    /// </summary>
    public class MfaSetupModel
    {
        /// <summary>
        /// key property
        /// </summary>
        /// <value></value>
        public string key {get;set;} = string.Empty;
        /// <summary>
        /// url property
        /// </summary>
        /// <value></value>
        public string url {get;set;} = string.Empty;
        /// <summary>
        /// otp property
        /// </summary>
        /// <value></value>
        public string otp {get;set;} = string.Empty;
        /// <summary>
        /// user id property
        /// </summary>
        /// <value></value>
        public string userId {get; set;} = string.Empty;
    }
}