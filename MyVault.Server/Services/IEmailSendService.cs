using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Server.Services
{
    /// <summary>
    /// interface class for email service
    /// </summary>
    public interface IEmailSendService
    {
        /// <summary>
        /// method to send a mail
        /// </summary>
        /// <param name="toEmail"></param>
        /// <param name="subject"></param>
        /// <param name="templateName"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        public Task sendMailAsync(string toEmail, string subject, string templateName, object model);
    }
}