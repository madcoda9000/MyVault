using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MyVault.Server.Models.BusinessModels;

namespace MyVault.Server.Services
{
    /// <summary>
    /// settings class
    /// </summary>
    public interface ISettingsService
    {
        /// <summary>
        /// property global settings
        /// </summary>
        /// <value>GlobalSettings</value>
        GlobalSettings Global { get; }
        /// <summary>
        /// property mail settings
        /// </summary>
        /// <value>MailSettings</value>
        MailSettings Mail { get; }
        /// <summary>
        /// property mail settings
        /// </summary>
        /// <value>MailSettings</value>
        LdapSettings Ldap { get; }
        /// <summary>
        /// property brand settings
        /// </summary>
        /// <value>MailSettings</value>
        BrandSettings Brand { get; }
        /// <summary>
        /// property brand settings
        /// </summary>
        /// <value>MailSettings</value>
        NotificationSettings Notif { get; }
        /// <summary>
        /// save method
        /// </summary>
        Task Save();
    }
}