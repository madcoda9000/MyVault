using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MyVault.Server.Services;

namespace MyVault.Server.Models.BusinessModels
{
    /// <summary>
    /// class to define ldap settings
    /// </summary>
    public class LdapSettings : AppSettingsBase
    {
        /// <summary>
        /// domain controller property
        /// </summary>
        /// <value>string</value>
        public string? LdapDomainController { get; set; }
        /// <summary>
        /// domain name property
        /// </summary>
        /// <value>string</value>
        public string? LdapDomainName { get; set; }
        /// <summary>
        /// domain base dn property
        /// </summary>
        /// <value>string</value>
        public string? LdapBaseDn { get; set; }
        /// <summary>
        /// domain group name property
        /// </summary>
        /// <value>string</value>
        public string? LdapGroup { get; set; }
        /// <summary>
        /// ldap enabled property
        /// </summary>
        /// <value>bool</value>
        public bool LdapEnabled { get; set; }
    }
}