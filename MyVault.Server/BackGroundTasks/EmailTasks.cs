using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Shared.Models.DataModels;
using MyVault.Shared.Models.FormModels;
using MyVault.Server.Services;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using RazorLight;

namespace MyVault.Server.BackGroundTasks
{

    /// <summary>
    /// interface for class emailtasks
    /// </summary>
    public interface IEmailTasks : IHostedService
    {
    }

    /// <summary>
    /// class emailtasks
    /// </summary>
    public class EmailTasks : IEmailTasks
    {
        /// <summary>
        /// internal EmailTasks field
        /// </summary>
        public static EmailTasks? Instance;
        /// <summary>
        /// ILogger field
        /// </summary>
        private readonly ILogger<EmailTasks> logger;
        /// <summary>
        /// Timer field
        /// </summary>
        private Timer? timer;
        /// <summary>
        /// internal int field for counter
        /// </summary>
        private int number;
        /// <summary>
        /// scope factory
        /// </summary>
        private readonly IServiceScopeFactory _serviceScopeFactory;
        /// <summary>
        /// IHostedServiceStatus
        /// </summary>
        private readonly IHostedServiceStatus _serviceSatus;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="stat"></param>
        /// <param name="serviceScopeFactory"></param>
        /// <param name="logger"></param>
        public EmailTasks(IHostedServiceStatus stat, IServiceScopeFactory serviceScopeFactory, ILogger<EmailTasks> logger)
        {
            this.logger = logger;
            this._serviceScopeFactory = serviceScopeFactory;
            this._serviceSatus = stat;

            if (Instance == null)
            {
                Instance = this;
            }
        }

        /// <summary>
        /// dispose method
        /// </summary>
        public void Dispose()
        {
            timer?.Dispose();
        }

        /// <summary>
        /// startAsync method
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (_serviceSatus.IsEmailServiceRunning == false) { _serviceSatus.IsEmailServiceRunning = true; }
            logger.LogInformation($"ESVC: Email service started...");
            timer = new Timer(o =>
            {
                Interlocked.Increment(ref number);
                using (var scope = _serviceScopeFactory.CreateScope())
                {
                    if (scope != null && scope.ServiceProvider != null)
                    {
                        AppDbContext _context = scope.ServiceProvider.GetService<AppDbContext>() ?? throw new Exception("Unable to create scoped AppDbContext.");
                        EmailHelper _emailHelper = scope.ServiceProvider.GetService<EmailHelper>() ?? throw new Exception("Unable to create scoped EmailHelper.");

                        var res = _context!.EmailJobs!.Where(j => j.Finished == false).ToList();
                        if (res != null && res.Count > 0)
                        {
                            logger.LogInformation($"ESVC: " + res.Count() + " jobs found. Start sending mails now.");
                            foreach (EmailJob job in res)
                            {
                                Object? cmd = null;
                                if(job.Template=="ObjectMail") {
                                    cmd = JsonSerializer.Deserialize<MailObjectNotifyModel>(job.objectModel!);
                                } else if(job.Template=="WelcomeCreateLdap" || job.Template=="WelcomeCreate" || job.Template=="ResetPw2" || job.Template=="ResetPw1" || job.Template=="WelcomeRegister" || job.Template=="MailConfirm") {
                                    cmd = JsonSerializer.Deserialize<MailConfirmModel>(job.objectModel!);
                                }
                                
                                if(cmd!=null) {
                                    var erg = Task.Run(async()=>await _emailHelper.sendMailAsync(job.Receiver, job.Subject, job.Template, cmd));
                                    if (erg.Result && erg.Result==true)
                                    {
                                        job.Finished = true;
                                        job.FinishedOn = DateTime.UtcNow;
                                        _context.EmailJobs!.Update(job);
                                        _context.SaveChanges();
                                        logger.LogInformation($"ESVC: email job " + job.Id + " completed with status success");
                                    }
                                    else
                                    {
                                        logger.LogInformation($"ESVC: email job " + job.Id + " completed with status failed");
                                    }
                                }
                            }
                        }
                        else if (res == null) { logger.LogError($"ESVC: Unable ton fetch jobs!"); }
                        else { logger.LogInformation($"ESVC: no open jobs. Quitting until next cycle."); }
                    }
                }
            },
            null,
            TimeSpan.Zero,
            TimeSpan.FromSeconds(120));

            return Task.CompletedTask;
        }

        /// <summary>
        /// stopAsync method
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task StopAsync(CancellationToken cancellationToken)
        {
            if (_serviceSatus.IsEmailServiceRunning == true) { _serviceSatus.IsEmailServiceRunning = false; }
            if (timer != null)
            {
                timer.Dispose();
                if (number > 0)
                {
                    number = 0;
                }
                logger.LogInformation($"ESVC: Email service stopped...");
            }
            return Task.CompletedTask;
        } 
    }
}