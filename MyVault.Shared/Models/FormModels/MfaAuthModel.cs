using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// mfa auth model
    /// </summary>
    public class MfaAuthModel
    {
        /// <summary>
        /// user id property
        /// </summary>
        /// <value></value>
        public string userId {get;set;} = string.Empty;
        /// <summary>
        /// otp property
        /// </summary>
        /// <value></value>
        public string otp {get;set;} = string.Empty;
    }
}