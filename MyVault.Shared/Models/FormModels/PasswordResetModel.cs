using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// form post model to set anew password
    /// </summary>
    public class PasswordResetModel
    {
        /// <summary>
        /// password property
        /// </summary>
        /// <value>string</value>
        public string? Password { get; set;} = string.Empty;
        /// <summary>
        /// user id property
        /// </summary>
        /// <value>string</value>
        public string? UserId { get; set;} = string.Empty;
        /// <summary>
        /// token property
        /// </summary>
        /// <value>string</value>
        public string? Token { get; set;} = string.Empty;

    }
}