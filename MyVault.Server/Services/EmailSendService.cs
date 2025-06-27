using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using RazorLight;

namespace MyVault.Server.Services
{
    /// <summary>
    /// clas for email send service
    /// </summary>
    public class EmailSendService : IEmailSendService
    {
        /// <summary>
        /// settings service injection
        /// </summary>
        private readonly ISettingsService _sett;
        /// <summary>
        /// razor engine injection
        /// </summary>
        private readonly IRazorLightEngine _razorEngine;
        /// <summary>
        /// logger property
        /// </summary>
        private readonly ILogger<EmailSendService> _logger;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="sett"></param>
        /// <param name="eng"></param>
        /// <param name="log"></param>
        public EmailSendService(ISettingsService sett, IRazorLightEngine eng, ILogger<EmailSendService> log) {
            _sett = sett;
            _razorEngine = eng;
            _logger = log;
        }

        /// <summary>
        /// send mail async method
        /// </summary>
        /// <param name="toEmail"></param>
        /// <param name="subject"></param>
        /// <param name="templateName"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task sendMailAsync(string toEmail, string subject, string templateName, object model) {
            var template = await _razorEngine.CompileRenderAsync(templateName, model);

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_sett.Mail.SmtpFromAddress, _sett.Mail.SmtpFromAddress));
            message.To.Add(new MailboxAddress(toEmail, toEmail));
            message.Subject = subject;
            message.Body = new TextPart("html")
            {
                Text = template
            };

            using (var client = new SmtpClient())
            {
                client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                await client.ConnectAsync(_sett.Mail.SmtpServer, int.Parse(_sett.Mail.SmtpPort!), SecureSocketOptions.StartTls);
                await client.AuthenticateAsync(_sett.Mail.SmtpUsername, _sett.Mail.SmtpPassword);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);
                _logger.LogInformation("MAIL: sended email " + templateName + " to " + toEmail);
            }
        }
    }
}