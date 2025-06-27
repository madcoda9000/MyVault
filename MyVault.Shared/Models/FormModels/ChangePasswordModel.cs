using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// change password model
    /// </summary>
    public class ChangePasswordModel
    {
        /// <summary>
        /// property userid
        /// </summary>
        /// <value></value>
        public string userId {get;set;} = string.Empty;
        /// <summary>
        /// property old password
        /// </summary>
        /// <value></value>
        public string oldPw {get;set;} = string.Empty;
        /// <summary>
        /// property new password
        /// </summary>
        /// <value></value>
        public string newPw {get;set;} = string.Empty;
    }
}