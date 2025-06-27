using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Server.Models.BusinessModels;
using MyVault.Shared.Models.DataModels;
using MyVault.Shared.Models.FormModels;
using MyVault.Shared.Models.Identity;
using MyVault.Server.Services;
using MyVault.Shared.Models.Auth;

namespace MyVault.Server.Controllers
{
     /// <summary>
     /// settings controller class
     /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class SettingsController : ControllerBase
    {
        /// <summary>
        /// usermanager property
        /// </summary>
        private readonly UserManager<AppUser> _userManager;
        /// <summary>
        /// rolemanager property
        /// </summary>
        private readonly RoleManager<IdentityRole> _roleManager;
        /// <summary>
        /// configuration property
        /// </summary>
        private readonly IConfiguration _configuration;
        /// <summary>
        /// dbcontext property
        /// </summary>
        private readonly AppDbContext _context;
        /// <summary>
        /// settings service property
        /// </summary>
        private readonly ISettingsService _sett;
        /// <summary>
        /// logger property
        /// </summary>
        private readonly ILogger<SettingsController> _logger;
        /// <summary>
        /// email service property
        /// </summary>
        private readonly IEmailSendService _mail;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="mail"></param>
        /// <param name="sett"></param>
        /// <param name="us"></param>
        /// <param name="rol"></param>
        /// <param name="conf"></param>
        /// <param name="cont"></param>
        /// <param name="log"></param>
        public SettingsController(IEmailSendService mail, ISettingsService sett, UserManager<AppUser> us, RoleManager<IdentityRole> rol, IConfiguration conf, AppDbContext cont, ILogger<SettingsController> log) {
            _userManager = us;
            _roleManager = rol;
            _configuration = conf;
            _sett = sett;
            _context = cont;
            _logger = log;
            _mail = mail;
        }

        /// <summary>
        /// feth appsettings without authentication
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("getOpenAppSettings")]
        public IActionResult GetOpenAppSettings() {
            var viewModel = new GlobalSettings();
            viewModel = _sett.Global;
            ApiResponse<GlobalSettings> res = new ApiResponse<GlobalSettings>();
            res.Success = true;
            res.Data = viewModel;
            return Ok(res);
        }

        /// <summary>
        /// fetch appsettings authenticated
        /// </summary>
        /// <returns></returns>
        [Authorize]
        [HttpGet]
        [Route("getAppSettings")]
        public IActionResult GetAppSettings() {
            var viewModel = new GlobalSettings();
            viewModel = _sett.Global;
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed application settings! ");
            ApiResponse<GlobalSettings> res = new ApiResponse<GlobalSettings>();
            res.Success = true;
            res.Data = viewModel;
            return Ok(res);
        }

        /// <summary>
        /// update app settings
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles="Admin")]
        [HttpPost]
        [Route("updateAppSettings")]
        public async Task<IActionResult> UpdateAppSettings([FromBody] GlobalSettings model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            if(model==null) {
                res.Success = false;
                res.Message = "AppSettingsModel should not be null!";
                return Ok(res);
            }

            _sett.Global.SessionCookieExpiration = model.SessionCookieExpiration;
            _sett.Global.SessionTimeoutRedirAfter = model.SessionTimeoutRedirAfter;
            _sett.Global.SessionTimeoutWarnAfter = model.SessionTimeoutWarnAfter;
            _sett.Global.ShowMfaEnableBanner = model.ShowMfaEnableBanner;
            _sett.Global.AllowSelfPwReset = model.AllowSelfPwReset;
            _sett.Global.AllowSelfRegister = model.AllowSelfRegister;
            await _sett.Save();
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " modified Application settings! ");

            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "modification",
                    objectType = "Settings",
                    objectName = "App Settings",
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod.objectType + " Object " + cmod.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }

            res.Success = true;
            return Ok(res);
        }

        /// <summary>
        /// fetch brand setting without authentication
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("getOpenBrandSettings")]
        public IActionResult GetOpenBrandSettings() {
            var viewModel = new BrandSettings();
            viewModel = _sett.Brand;
            ApiResponse<BrandSettings> res = new ApiResponse<BrandSettings>();
            res.Success = true;
            res.Data = viewModel;
            return Ok(viewModel);
        }

        /// <summary>
        /// fetch brand settings authenticated
        /// </summary>
        /// <returns></returns>
        [Authorize]
        [HttpGet]
        [Route("getBrandSettings")]
        public IActionResult GetBrandSettings() {
            var viewModel = new BrandSettings();
            viewModel = _sett.Brand;
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed Brand settings! ");
            ApiResponse<BrandSettings> res = new ApiResponse<BrandSettings>();
            res.Success = true;
            res.Data = viewModel;
            return Ok(viewModel);
        }

        /// <summary>
        /// update brand settings
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles="Admin")]
        [HttpPost]
        [Route("updateBrandSettings")]
        public async Task<IActionResult> UpdateBrandSettings([FromBody] BrandSettings model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            if(model==null) {
                res.Success = false;
                res.Message = "BrandSettingsModel should not be null!";
                return Ok(res);
            }

            _sett.Brand.ApplicationLogo = model.ApplicationLogo;
            _sett.Brand.LoginBackground = model.LoginBackground;
            _sett.Brand.ApplicationName = model.ApplicationName;
            _sett.Brand.ColorDanger = model.ColorDanger;
            _sett.Brand.ColorHeadlines = model.ColorHeadlines;
            _sett.Brand.ColorInfo = model.ColorInfo;
            _sett.Brand.ColorLightBackground = model.ColorLightBackground;
            _sett.Brand.ColorLink = model.ColorLink;
            _sett.Brand.ColorPrimary = model.ColorPrimary;
            _sett.Brand.ColorSecondary = model.ColorSecondary;
            _sett.Brand.ColorSuccess = model.ColorSuccess;
            _sett.Brand.ColorTextMuted = model.ColorTextMuted;
            _sett.Brand.ColorWarning = model.ColorWarning;
            _sett.Brand.HeadBarBackground = model.HeadBarBackground;
            _sett.Brand.SideBarBackground = model.SideBarBackground;
            _sett.Brand.HeadBarTextColor = model.HeadBarTextColor;
            _sett.Brand.EnableCarbonStyle = model.EnableCarbonStyle;
            await _sett.Save();

            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " modified Brand settings! ");

            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "modification",
                    objectType = "Settings",
                    objectName = "Brand Settings",
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod.objectType + " Object " + cmod.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }

            res.Success = true;
            return Ok(res);
        }

        /// <summary>
        /// fetch ldap settings
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("getLdapSettings")]
        public IActionResult GetLdapSettings() {
            var viewmodel = new LdapSettings();
            viewmodel = _sett.Ldap;
            ApiResponse<LdapSettings> res = new ApiResponse<LdapSettings>();
            res.Success = true;
            res.Data = viewmodel;
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed Ldap settings! ");
            return Ok(res);
        }

        /// <summary>
        /// update ldap settings
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles="Admin")]
        [HttpPost]
        [Route("updateLdapSettings")]
        public async Task<IActionResult> UpdateLdappSettings([FromBody] LdapSettings model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            if(model==null) {
                res.Success = false;
                res.Message = "LdapSettingsModel should not be null!";
                return Ok(res);
            }

            _sett.Ldap.LdapBaseDn = model.LdapBaseDn;
            _sett.Ldap.LdapDomainController = model.LdapDomainController;
            _sett.Ldap.LdapDomainName = model.LdapDomainName;
            _sett.Ldap.LdapGroup = model.LdapGroup;
            _sett.Ldap.LdapEnabled = model.LdapEnabled;
            await _sett.Save();

            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " modified Ldap settings! ");
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "modification",
                    objectType = "Settings",
                    objectName = "LDAP Settings",
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod.objectType + " Object " + cmod.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }
            res.Success = true;
            return Ok(res);
        }

        /// <summary>
        /// fetch mail settings
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("getMailSettings")]
        public IActionResult GetMailSettings() {
            var viewmodel = new MailSettings();
            viewmodel = _sett.Mail;
            ApiResponse<MailSettings> res = new ApiResponse<MailSettings>();
            res.Success = true;
            res.Data = viewmodel;
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed Mail settings! ");
            return Ok(res);
        }

        /// <summary>
        /// update mail settings
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles="Admin")]
        [HttpPost]
        [Route("updateMailSettings")]
        public async Task<IActionResult> UpdateMailSettings([FromBody] MailSettings model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            if(model==null) {
                res.Success = false;
                res.Message = "MailSettingsModel should not be null!";
                return Ok(res);
            }

            _sett.Mail.SmtpFromAddress = model.SmtpFromAddress;
            _sett.Mail.SmtpPassword = model.SmtpPassword;
            _sett.Mail.SmtpPort = model.SmtpPort;
            _sett.Mail.SmtpServer = model.SmtpServer;
            _sett.Mail.SmtpUsername = model.SmtpUsername;
            _sett.Mail.SmtpUseTls = model.SmtpUseTls;
            await _sett.Save();

            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "modification",
                    objectType = "Settings",
                    objectName = "Mail Settings",
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod.objectType + " Object " + cmod.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }

            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " modified Mail settings! ");

            res.Success = true;
            return Ok(res);
        }


        /// <summary>
        /// fetch notification settings
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("getNotifSettings")]
        public IActionResult GetNotifSettings() {
            var viewmodel = new NotificationSettings();
            viewmodel = _sett.Notif;
            ApiResponse<NotificationSettings> res = new ApiResponse<NotificationSettings>();
            res.Success = true;
            res.Data = viewmodel;
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewwed Notification settings! ");
            return Ok(res);
        }

        /// <summary>
        /// update notification settings
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles="Admin")]
        [HttpPost]
        [Route("updateNotifSettings")]
        public async Task<IActionResult> UpdateNotifSettings([FromBody] NotificationSettings model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            if(model==null) {
                res.Success = false;
                res.Message = "NotificationSettingsModel should not be null!";                
                return Ok(res);
            }

            _sett.Notif.NotificationReceiver = model.NotificationReceiver;
            _sett.Notif.SendNotifOnObjectCreation = model.SendNotifOnObjectCreation;
            _sett.Notif.SendNotifOnObjectDeletion = model.SendNotifOnObjectDeletion;
            _sett.Notif.SendNotifOnObjectUpdate = model.SendNotifOnObjectUpdate;
            _sett.Notif.SendNotifOnUserSelfRegister = model.SendNotifOnUserSelfRegister;
            _sett.Notif.SendWelcomeMailOnUserCreation = model.SendWelcomeMailOnUserCreation;
            await _sett.Save();

            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "modification",
                    objectType = "Settings",
                    objectName = "Notifications Settings",
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod.objectType + " Object " + cmod.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }

            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " modified Notification settings! ");

            res.Success = true;
            return Ok(res);
        }
    }
}