using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// maiol object nitofy model
    /// </summary>
    public class MailObjectNotifyModel
    {
        /// <summary>
        /// object type property
        /// </summary>
        /// <value></value>
        public string objectType {get;set;} = string.Empty;
        /// <summary>
        /// object name property
        /// </summary>
        /// <value></value>
        public string objectName {get;set;} = string.Empty;
        /// <summary>
        /// object action property
        /// </summary>
        /// <value></value>
        public string objectAction {get; set;} = string.Empty;
        /// <summary>
        /// executed by property
        /// </summary>
        /// <value></value>
        public string executedBy {get; set;} = string.Empty;
    }
}