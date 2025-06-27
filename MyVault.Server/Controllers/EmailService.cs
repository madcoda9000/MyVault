using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MyVault.Server.BackGroundTasks;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Shared.Models.DataModels;
using MyVault.Shared.Models.FormModels;
using MyVault.Shared.Models.Identity;
using MyVault.Server.Services;
using MyVault.Shared.Models.Auth;

namespace MyVault.Server.Controllers
{
    /// <summary>
    /// email servcie class
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin ")]
    public class EmailService : ControllerBase
    {
        /// <summary>
        /// dbcontext property
        /// </summary>
        private readonly AppDbContext _context;
        /// <summary>
        /// usermanager property
        /// </summary>
        private readonly UserManager<AppUser> _userManager;
        /// <summary>
        /// rolemanager property
        /// </summary>
        private readonly RoleManager<IdentityRole> _roleManager;
        /// <summary>
        /// ILogger property
        /// </summary>
        private readonly ILogger<EmailService> _logger;
        /// <summary>
        /// ISettings property
        /// </summary>
        private readonly ISettingsService _sett;
        /// <summary>
        /// IHostedService property
        /// </summary>
        private readonly IHostedServiceStatus _serviceSatus;
        /// <summary>
        /// Emailtasks property
        /// </summary>
        private readonly IEmailTasks _EmailJobs;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="emailjobs"></param>
        /// <param name="serviceSatus"></param>
        /// <param name="sett"></param>
        /// <param name="us"></param>
        /// <param name="rol"></param>
        /// <param name="cont"></param>
        /// <param name="log"></param>
        public EmailService(IEmailTasks emailjobs, IHostedServiceStatus serviceSatus, ISettingsService sett, UserManager<AppUser> us, RoleManager<IdentityRole> rol, AppDbContext cont, ILogger<EmailService> log) {
            _userManager = us;
            _roleManager = rol;
            _context = cont;
            _logger = log;
            _sett = sett;
            _serviceSatus = serviceSatus;
            _EmailJobs = emailjobs;
        }

        /// <summary>
        /// method to stop email send service
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("stopEmailService")]
        public async Task<IActionResult> StopEmailService() {
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " stopped email service");
            await _EmailJobs.StopAsync(new System.Threading.CancellationToken());
            ApiResponse<Boolean> res = new ApiResponse<bool>();
            res.Success = true;
            res.Data = true;
            return Ok(res);
        }

        /// <summary>
        /// method to stop email service
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("startEmailService")]
        public async Task<IActionResult> StartEmailService() {
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " started email service");
            await _EmailJobs.StartAsync(new System.Threading.CancellationToken());
            ApiResponse<Boolean> res = new ApiResponse<bool>();
            res.Success = true;
            res.Data = true;
            return Ok(res);
        }

        /// <summary>
        /// method to get email service status
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("getEmailServiceStatus")]
        public ActionResult GetEmailServiceStatus() {
            var res = new ApiResponse<Boolean>();
            
            if(_serviceSatus!=null && _serviceSatus.IsEmailServiceRunning==true) {
                res.Success = true;
                res.Data = true;
            }else if(_serviceSatus!=null && _serviceSatus.IsEmailServiceRunning==false) {
                res.Success = true;
                res.Data = false;
            }
            return Ok(res);
        }

        /// <summary>
        /// method to fetch email send service logs
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("getEsvcLogs")]
        public async Task<IActionResult> GetEsvcLogs([FromBody] PagedPostModel model)
        {
            ApiResponse<PagedData<AppLogsDto>> res = new ApiResponse<PagedData<AppLogsDto>>();

            var query = _context.AppLogs!
                .AsNoTracking()
                .Where(l => l.Subject.ToLower().StartsWith("esvc:") || l.Subject.ToLower().StartsWith("mail:"));

            if (!string.IsNullOrEmpty(model.searchValue))
            {
                var search = model.searchValue.ToLower();
                query = query.Where(s => s.Subject.ToLower().Contains(search));
            }

            var logs = await query
                .OrderByDescending(l => l.Timestamp)
                .Select(a => new AppLogsDto
                {
                    Id = a.Id,
                    Timestamp = a.Timestamp,
                    LogLevel = a.LogLevel,
                    Category = a.Category,
                    Subject = a.Subject,
                    Exception = a.Exception
                })
                .ToListAsync();

            var pagedData = Pagination.PagedResult(logs, model.page, model.pageSize);

            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed Email service logs");

            res.Success = true;
            res.Data = pagedData;
            return Ok(res);
        }


        /// <summary>
        /// method to fetch waiting email jobs
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("getWaitingEmailJobs")]
        public async Task<IActionResult> GetWaitingEmailJobs([FromBody] PagedPostModel model)
        {
            ApiResponse<PagedData<EmailJob>> res = new ApiResponse<PagedData<EmailJob>>();
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed all waiting mail jobs");
            var erg = await _context.EmailJobs!.Where(l => l.Finished == false).OrderByDescending(l=>l.CreatedOn).ToListAsync();
            if(!String.IsNullOrEmpty(model.searchValue)) {
                erg = erg.Where(s=>s.Subject.ToLower().Contains(model.searchValue.ToLower())).OrderByDescending(l=>l.CreatedOn).ToList();
            }
            var pagedData = Pagination.PagedResult(erg, model.page, model.pageSize);
            res.Success = true;
            res.Data = pagedData;
            return Ok(res);
        }

        /// <summary>
        /// method to fetch finished email jobs
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("getFinishedEmailJobs")]
        public async Task<IActionResult> GetFinishedEmailJobs([FromBody] PagedPostModel model)
        {
            ApiResponse<PagedData<EmailJob>> res = new ApiResponse<PagedData<EmailJob>>();
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed all finished mail jobs");
            var erg = await _context.EmailJobs!.Where(l => l.Finished == true).OrderByDescending(l=>l.CreatedOn).ToListAsync();
            if(!String.IsNullOrEmpty(model.searchValue)) {
                erg = erg.Where(s=>s.Subject.ToLower().Contains(model.searchValue.ToLower())).OrderByDescending(l=>l.FinishedOn).ToList();
            }
            var pagedData = Pagination.PagedResult(erg, model.page, model.pageSize);
            res.Success = true;
            res.Data = pagedData;
            return Ok(res);
        } 

        
        #region "INTERNAL VALIDATION METHODS"
        /// <summary>
        /// check if a user has the permission for a secret
        /// </summary>
        /// <param name="SecretId"></param>
        /// <returns></returns>
        private async Task<Boolean> CheckIfUserHasSecretPermission(int SecretId)
        {
            var us = await _userManager.FindByNameAsync(User.Identity!.Name!);
            var res = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id == SecretId);
            if (res == null || us == null) { return false; }
            if (us.RolesCombined!.ToLower().Contains("admin") == true) { return true; }
            if (us.RolesCombined!.ToLower().Contains("user") == true && res.S_createdBy.ToLower() == us.UserName!.ToLower()) { return true; }
            if (us.RolesCombined!.ToLower().Contains(res.S_UserRoles!.ToLower()) == true) { return true; }
            return false;
        }

        /// <summary>
        /// check if user a member of role
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        private async Task<Boolean> CheckIfUserHasRolePermission(String roleName)
        {
            var erg = await _roleManager.FindByNameAsync(roleName);
            if (erg == null) { return false; }
            var us = await GetCurrentUser();
            if (us == null) { return false; }
            if (us.RolesCombined!.ToLower().Contains(roleName.ToLower())) { return true; }
            return false;
        }

        /// <summary>
        /// get the current user context
        /// </summary>
        /// <returns></returns>
        private async Task<AppUser> GetCurrentUser()
        {
            var us = await _userManager.FindByNameAsync(User.Identity!.Name!);
            if(us!=null) { return us; }else { return null!; }
        }

        #endregion
        
    }
}