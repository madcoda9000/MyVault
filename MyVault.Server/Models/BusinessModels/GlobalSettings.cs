using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MyVault.Server.Services;

namespace MyVault.Server.Models.BusinessModels
{
    /// <summary>
    /// class to define a global settings object
    /// </summary>
    public class GlobalSettings : AppSettingsBase
    {
        /// <summary>
        /// property SessionTimeoutWarnAfter
        /// </summary>
        /// <value>string</value>
        public string? SessionTimeoutWarnAfter { get; set; }
        /// <summary>
        /// property SessionTimeoutRedirAfter
        /// </summary>
        /// <value>string</value>
        public string? SessionTimeoutRedirAfter { get; set; }
        /// <summary>
        /// property SessionCookieExpiration
        /// </summary>
        /// <value>string</value>
        public string? SessionCookieExpiration { get; set; }
        /// <summary>
        /// mfa warning property
        /// </summary>
        /// <value></value>
        public bool ShowMfaEnableBanner { get; set; }
        /// <summary>
        /// mfa banner property
        /// </summary>
        /// <value></value>
        public bool AllowSelfRegister {get;set;}
        /// <summary>
        /// allow self pw reset property
        /// </summary>
        /// <value></value>
        public bool AllowSelfPwReset {get;set;}
    }
}