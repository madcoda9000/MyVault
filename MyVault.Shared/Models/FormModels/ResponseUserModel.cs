using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// reposne user model
    /// </summary>
    public class ResponseUserModel
    {
        /// <summary>
        /// birthday property
        /// </summary>
        /// <value></value>
        public DateTime BirthDay {get; set;} = DateTime.Now;
        /// <summary>
        /// created timestamp
        /// </summary>
        /// <value></value>
        public DateTime CreatedOn {get; set;} = DateTime.Now;
        /// <summary>
        /// department property
        /// </summary>
        /// <value></value>
        public string Department {get;set;} = string.Empty;
        /// <summary>
        /// email property
        /// </summary>
        /// <value></value>
        public string Email {get;set;} = string.Empty;
        /// <summary>
        /// firstname property
        /// </summary>
        /// <value></value>
        public string FirstName {get;set;} = string.Empty;
        /// <summary>
        /// lastname property
        /// </summary>
        /// <value></value>
        public string LastName {get;set;} = string.Empty;
        /// <summary>
        /// id property
        /// </summary>
        /// <value></value>
        public string Id  {get;set;} = string.Empty;
        /// <summary>
        /// lockout peroperty
        /// </summary>
        /// <value></value>
        public bool IsLockoutEnabled {get;set;}
        /// <summary>
        /// ldap property
        /// </summary>
        /// <value></value>
        public bool IsLdapLogin {get;set;}
        /// <summary>
        /// mfa enforce property
        /// </summary>
        /// <value></value>
        public bool IsMfaForce {get;set;}
        /// <summary>
        /// phone number rpoperty
        /// </summary>
        /// <value></value>
        public string PhoneNumber {get;set;} = string.Empty;
        /// <summary>
        /// roles property
        /// </summary>
        /// <value></value>
        public string RolesCombined {get;set;} = string.Empty;
        /// <summary>
        /// username property
        /// </summary>
        /// <value></value>
        public string UserName {get;set;} = string.Empty;
        /// <summary>
        /// mfa enbaled property
        /// </summary>
        /// <value></value>
        public bool TwoFactorEnabled {get; set;}
    }
}