using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// upadte user model
    /// </summary>
    public class UpdateUserModel
    {
        /// <summary>
        /// user id
        /// </summary>
        /// <value></value>
        public string uId {get;set;} = string.Empty;
        /// <summary>
        /// username
        /// </summary>
        /// <value></value>
        public string uName {get;set;} = string.Empty;
        /// <summary>
        /// user email
        /// </summary>
        /// <value></value>
        public string uEmail {get;set;} = string.Empty;
        /// <summary>
        /// user password
        /// </summary>
        /// <value></value>
        public string uPasswd {get;set;} = string.Empty;
        /// <summary>
        /// enforce mfa property
        /// </summary>
        /// <value></value>
        public bool uEnforceMfa {get;set;}
        /// <summary>
        /// ldap property
        /// </summary>
        /// <value></value>
        public bool uLdap {get;set;}
        /// <summary>
        /// roles property
        /// </summary>
        /// <value></value>
        public string uRoles {get;set;} = string.Empty;
        /// <summary>
        /// users firstname
        /// </summary>
        /// <value></value>
        public string uFirstName {get;set;} = string.Empty;
        /// <summary>
        /// users lastname
        /// </summary>
        /// <value></value>
        public string uLastName {get;set;} = string.Empty;
    }
}