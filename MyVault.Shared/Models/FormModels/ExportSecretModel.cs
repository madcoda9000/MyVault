using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// export secret model
    /// </summary>
    public class ExportSecretModel
    {
        /// <summary>
        /// name property
        /// </summary>
        /// <value></value>
        public string? S_Name { get; set; }
        /// <summary>
        /// hostname property
        /// </summary>
        /// <value></value>
        public string S_HostName { get; set; } = String.Empty;
        /// <summary>
        /// property url
        /// </summary>
        /// <value></value>
        public string S_Url { get; set; } = String.Empty;
        /// <summary>
        /// property username
        /// </summary>
        /// <value></value>
        public string S_Username { get; set; } = String.Empty;
        /// <summary>
        /// property password
        /// </summary>
        /// <value></value>
        public string S_Password { get; set; } = String.Empty;
        /// <summary>
        /// property description
        /// </summary>
        /// <value></value>
        public string S_Description { get; set; } = String.Empty;
        /// <summary>
        /// property user roles
        /// </summary>
        /// <value></value>
        public string S_UserRoles { get; set; } = String.Empty;

    }
}