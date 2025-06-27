using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Server.BackGroundTasks
{
    /// <summary>
    /// IHostedService Interface
    /// </summary>
    public interface IHostedServiceStatus
    {
        /// <summary>
        /// get / set the status of email service
        /// </summary>
        /// <value></value>
        bool IsEmailServiceRunning { get; set; }
    }
}