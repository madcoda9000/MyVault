using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// upadte user data model
    /// </summary>
    public class UpdateUserDataModel
    {
        /// <summary>
        /// user id property
        /// </summary>
        /// <value></value>
        public string userId {get;set;} = string.Empty;
        /// <summary>
        /// first name property
        /// </summary>
        /// <value></value>
        public string fName {get;set;} = string.Empty;
        /// <summary>
        /// last name property
        /// </summary>
        /// <value></value>
        public string lName {get;set;} = string.Empty;
        /// <summary>
        /// email proeprty
        /// </summary>
        /// <value></value>
        public string email {get;set;} = string.Empty;
    }
}