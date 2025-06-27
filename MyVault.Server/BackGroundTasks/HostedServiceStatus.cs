using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Server.BackGroundTasks
{
    /// <summary>
    /// HostedService class inheriting from IHostedService Interface
    /// </summary>
    public class HostedServiceStatus : IHostedServiceStatus
    {
        /// <summary>
        /// get or set status of email service
        /// </summary>
        /// <value></value>
        public bool IsEmailServiceRunning { get; set; }
    }
}