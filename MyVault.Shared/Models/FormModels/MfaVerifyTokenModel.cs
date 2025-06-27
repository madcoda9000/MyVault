using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// mfa verify token model
    /// </summary>
    public class MfaVerifyTokenModel
    {
        /// <summary>
        /// mfa token property
        /// </summary>
        /// <value></value>
        public string mfaToken {get;set;} = string.Empty;
        /// <summary>
        /// user id property
        /// </summary>
        /// <value></value>
        public string userId {get;set;} = string.Empty;
    }
}