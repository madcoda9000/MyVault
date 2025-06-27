using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// update secret model
    /// </summary>
    public class UpdateSecretModel
    {
        /// <summary>
        /// id property
        /// </summary>
        /// <value></value>
        public int s_Id {get; set;} = 0;
        /// <summary>
        /// name proeprty
        /// </summary>
        /// <value></value>
        public string s_name {get;set;} = string.Empty;
        /// <summary>
        /// hostname property
        /// </summary>
        /// <value></value>
        public string s_hostname {get;set;} = string.Empty;
        /// <summary>
        /// url property
        /// </summary>
        /// <value></value>
        public string s_url {get;set;} = string.Empty;
        /// <summary>
        /// username property
        /// </summary>
        /// <value></value>
        public string s_username {get;set;} = string.Empty;
        /// <summary>
        /// password property
        /// </summary>
        /// <value></value>
        public string s_password {get;set;} = string.Empty;
        /// <summary>
        /// description property
        /// </summary>
        /// <value></value>
        public string s_description {get;set;} = string.Empty;
        /// <summary>
        ///  roles property
        /// </summary>
        /// <value></value>
        public string s_userroles {get;set;} = string.Empty;
    }
}