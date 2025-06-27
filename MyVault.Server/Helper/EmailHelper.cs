using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using RazorLight;
using MyVault.Server.Services;

namespace MyVault.Server.Helper
{
    /// <summary>
    /// email helper class
    /// </summary>
    public class EmailHelper
    {
        /// <summary>
        /// property settings service
        /// </summary>
        private readonly ISettingsService _sett;
        /// <summary>
        /// property razor engine
        /// </summary>
        private readonly IRazorLightEngine _razorEngine;
        /// <summary>
        /// property logger
        /// </summary>
        private readonly ILogger<EmailHelper> _logger;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="sett"></param>
        /// <param name="eng"></param>
        /// <param name="log"></param>
        public EmailHelper(ISettingsService sett, IRazorLightEngine eng, ILogger<EmailHelper> log) {
            _sett = sett;
            _razorEngine = eng;
            _logger = log;
        }

        /// <summary>
        /// method to send a mail
        /// </summary>
        /// <param name="toEmail"></param>
        /// <param name="subject"></param>
        /// <param name="templateName"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task<bool> sendMailAsync(string toEmail, string subject, string templateName, object model) {
            var template = await _razorEngine.CompileRenderAsync(templateName, model);

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_sett.Mail.SmtpFromAddress, _sett.Mail.SmtpFromAddress));
            message.To.Add(new MailboxAddress(toEmail, toEmail));
            message.Subject = subject;
            message.Body = new TextPart("html")
            {
                Text = template
            };
 
            try {
                using (var client = new SmtpClient())
                {
                    client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                    await client.ConnectAsync(_sett.Mail.SmtpServer, int.Parse(_sett.Mail.SmtpPort!), SecureSocketOptions.StartTls);
                    await client.AuthenticateAsync(_sett.Mail.SmtpUsername, _sett.Mail.SmtpPassword);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                    _logger.LogInformation("MAIL: sended email \"" + subject + "\" to " + toEmail);
                }

                return true;
            } catch (Exception ex) {
                 _logger.LogError("ESVC: Error while sending mail: " +  ex.Message);
                return false;
            }            
        }
    }
}