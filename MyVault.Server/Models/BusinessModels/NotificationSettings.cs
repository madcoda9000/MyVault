using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MyVault.Server.Services;

namespace MyVault.Server.Models.BusinessModels
{
    /// <summary>
    /// model class for notification settings
    /// </summary>
    public class NotificationSettings : AppSettingsBase
    {
        /// <summary>
        /// SendNotifOnObjectUpdate
        /// </summary>
        /// <value></value>
        public bool SendNotifOnObjectUpdate {get; set;}
        /// <summary>
        /// SendNotifOnObjectCreation
        /// </summary>
        /// <value></value>
        public bool SendNotifOnObjectCreation {get; set;}
        /// <summary>
        /// SendNotifOnObjectDeletion
        /// </summary>
        /// <value></value>
        public bool SendNotifOnObjectDeletion {get; set;}
        /// <summary>
        /// SendNotifOnUserSelfRegister
        /// </summary>
        /// <value></value>
        public bool SendNotifOnUserSelfRegister {get; set;}
        /// <summary>
        /// SendWelcomeMailOnUserCreation
        /// </summary>
        /// <value></value>
        public bool SendWelcomeMailOnUserCreation {get; set;}
        /// <summary>
        /// NotificationReceiver
        /// </summary>
        /// <value></value>
        public string NotificationReceiver {get; set;} = string.Empty;
    }
}