using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// verify secret model
    /// </summary>
    public class CheckIfSecretExistsModel
    {
        /// <summary>
        /// secret name property
        /// </summary>
        public string secretName {get;set;} = string.Empty;
        /// <summary>
        /// secret role property
        /// </summary>
        public string secretRole {get;set;} = string.Empty;
    }
}