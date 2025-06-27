using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// new user model
    /// </summary>
    public class NewUserModel
    {
        /// <summary>
        /// username proeprty
        /// </summary>
        /// <value></value>
        public string nName {get;set;} = string.Empty;
        /// <summary>
        /// email property
        /// </summary>
        /// <value></value>
        public string nEmail {get;set;} = string.Empty;
        /// <summary>
        /// password property
        /// </summary>
        /// <value></value>
        public string nPasswd {get;set;} = string.Empty;
        /// <summary>
        /// user roles property
        /// </summary>
        /// <value></value>
        public string nRoles {get;set;} = string.Empty;
        /// <summary>
        /// firstname property
        /// </summary>
        /// <value></value>
        public string nFirstName {get;set;} = string.Empty;
        /// <summary>
        /// lastname property
        /// </summary>
        /// <value></value>
        public string nLastName {get;set;} = string.Empty;
        /// <summary>
        /// ldap property
        /// </summary>
        /// <value></value>
        public bool nLdap {get;set;}
        /// <summary>
        /// mfa enforce property
        /// </summary>
        /// <value></value>
        public bool nEnforceMfa {get; set;}
    }
}