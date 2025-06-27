using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Shared.Models.DataModels;
using MyVault.Shared.Models.FormModels;
using MyVault.Shared.Models.Identity;
using MyVault.Shared.Models.Auth;

namespace MyVault.Server.Controllers
{
    /// <summary>
    /// model class for SystemLog entry
    /// </summary>
    public class SystemLogIdModel {
        /// <summary>
        /// id property
        /// </summary>
        public int id {get;set;}
    }

    /// <summary>
    /// LogController class
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class LogController : ControllerBase
    {
        /// <summary>
        /// dbcontext property
        /// </summary>
        private readonly AppDbContext _context;
        /// <summary>
        /// Logger property
        /// </summary>
        private readonly ILogger<LogController> _logger;
        /// <summary>
        /// usermanager property
        /// </summary>
        private readonly UserManager<AppUser> _userManager;
        /// <summary>
        /// rolemanager property
        /// </summary>
        private readonly RoleManager<IdentityRole> _roleManager;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="us"></param>
        /// <param name="rol"></param>
        /// <param name="conf"></param>
        /// <param name="cont"></param>
        /// <param name="log"></param>
        public LogController(UserManager<AppUser> us, RoleManager<IdentityRole> rol, IConfiguration conf, AppDbContext cont, ILogger<LogController> log) {
            _userManager = us;
            _roleManager = rol;
            _context = cont;
            _logger = log;
        }

        /// <summary>
        /// method to make an audit entry
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("makeAuditEntry")]
        public async Task<IActionResult> MakeAuditEntry([FromBody] AuditEntryModel model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            AppLogs log = new AppLogs();
            log.Timestamp = DateTime.Now;
            log.LogLevel = LogLevel.Information;
            log.Category = model.source;
            log.Subject = model.message;
            _context.AppLogs!.Add(log);
            await _context.SaveChangesAsync();

            res.Success = true;
            res.Data = true;
            return Ok(res);
        }

        /// <summary>
        /// method to fetch audit logs
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("getAuditLogs")]
        public async Task<IActionResult> GetAuditLogs([FromBody] PagedPostModel model) {
            ApiResponse<PagedData<AppLogs>> res = new ApiResponse<PagedData<AppLogs>>();
            var erg = await _context.AppLogs!.AsNoTracking().Where(l=>l.Subject.StartsWith("AUDIT:")==true).OrderByDescending(l=>l.Id).
                Select(a => new AppLogs{
                    Id = a.Id,
                    Timestamp = a.Timestamp,
                    LogLevel = a.LogLevel,
                    Category = a.Category,
                    Subject = a.Subject,
                    Data = string.Empty,
                    Exception = a.Exception
                })
            .ToListAsync();

            if(!String.IsNullOrEmpty(model.searchValue)) {
                erg = erg.Where(s=>s.Subject.ToLower().Contains(model.searchValue.ToLower())).OrderByDescending(l=>l.Id).ToList();
            }
            var pagedData = Pagination.PagedResult(erg, model.page, model.pageSize);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed  audit logs! ");
            res.Success = true;
            res.Data = pagedData;
            return  Ok(res);
        } 

        /// <summary>
        /// method to fetch system logs
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("getSystemLogs")]        
        public async Task<IActionResult> GetSystemLogs([FromBody] PagedPostModel model) {
            ApiResponse<PagedData<AppLogs>> res = new ApiResponse<PagedData<AppLogs>>();
            var erg = await _context.AppLogs!.AsNoTracking().Where(l=>l.Subject.StartsWith("AUDIT:")==false).OrderByDescending(l=>l.Id).
                Select(a => new AppLogs{
                    Id = a.Id,
                    Timestamp = a.Timestamp,
                    LogLevel = a.LogLevel,
                    Category = a.Category,
                    Subject = a.Subject,
                    Data = string.Empty,
                    Exception = a.Exception
                })
            .ToListAsync();
            if(!String.IsNullOrEmpty(model.searchValue)) {
                erg = erg.Where(s=>s.Subject.ToLower().Contains(model.searchValue.ToLower())).OrderByDescending(l=>l.Id).ToList();
            }
            var pagedData = Pagination.PagedResult(erg, model.page, model.pageSize);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed system logs! ");
            res.Success = true;
            res.Data = pagedData;
            return  Ok(res);
        }

        /// <summary>
        /// method to fetch data property from system log object
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("getSystemLogData")] 
        public async Task<IActionResult> GetSystemLogData([FromBody] SystemLogIdModel model) {
            ApiResponse<AppLogs> res = new ApiResponse<AppLogs>();
            var erg = await _context.AppLogs!.SingleAsync(l=>l.Id==model.id);
            if(erg!=null) {
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed details for log entry " + model.id + "! ");
                res.Success = true;
                res.Data = erg;
                return Ok(res);
            } else {
                _logger.LogWarning("AUDIT: " + User.Identity!.Name + " tried to view details for log entry " + model.id + ". But this entry does not exist.");
                res.Success = false;
                res.Data = null;
                res.Message = "No log entry for id " + model.id + " found!";
                return Ok(res);
            }
        }
    }
}