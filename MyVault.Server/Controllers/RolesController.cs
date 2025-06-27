using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MyVault.Shared.Models.Identity;
using MyVault.Shared.Models.FormModels;
using MyVault.Server.Data;
using Microsoft.AspNetCore.Authorization;
using MyVault.Server.Helper;
using MyVault.Server.Services;
using MyVault.Shared.Models.DataModels;
using System.Text.Json;
using MyVault.Shared.Models.Auth;

namespace MyVault.Server.Controllers
{
    /// <summary>
    /// model for role object
    /// </summary>
    public class RoleIdModel {
        /// <summary>
        /// id property
        /// </summary>
       public string id {get;set;}=string.Empty; 
    }

    /// <summary>
    /// roles controller class
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        /// <summary>
        /// rolemanager property
        /// </summary>
        private readonly RoleManager<IdentityRole> _roleManager;
        /// <summary>
        /// dbcontext property
        /// </summary>
        private readonly AppDbContext _context;
        /// <summary>
        /// logger property
        /// </summary>
        private readonly ILogger<SettingsController> _logger;
        /// <summary>
        /// usermanager property
        /// </summary>
        private readonly UserManager<AppUser> _userManager;
        /// <summary>
        /// settings service property
        /// </summary>
        private readonly ISettingsService _sett;
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
        /// <param name="cont"></param>
        /// <param name="log"></param>
        public RolesController(IEmailSendService mail, ISettingsService sett, UserManager<AppUser> us, RoleManager<IdentityRole> rol, AppDbContext cont, ILogger<SettingsController> log) {
            _roleManager = rol;
            _context = cont;
            _logger = log;
            _userManager = us;
            _sett = sett;
            _mail = mail;
        }

        /// <summary>
        /// method to check if a role exists
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("checkIfRoleExists")] 
        public async Task<IActionResult> CheckIfRoleExists([FromBody] NewRoleModel model) {
            ApiResponse<bool> resp = new ApiResponse<bool>();
            var erg = await _roleManager.FindByNameAsync(model.roleName);
            if(erg!=null) {
                resp.Success = true;
                resp.Data = true;
                return Ok(resp);
            } else {
                resp.Success = true;
                resp.Data = false;
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to create a role
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("createRole")] 
        public async Task<IActionResult> CreateRole([FromBody] NewRoleModel model) {
            ApiResponse<bool> res = new ApiResponse<bool>();

            AppRole rl = new AppRole();
            rl.Name = model.roleName;
            var erg = await _roleManager.CreateAsync(rl);
            if(erg.Succeeded) {
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " created role " + model.roleName + "! "); 
                // notify admin
                if (_sett.Notif.SendNotifOnObjectUpdate == true)
                {
                    var cmod = new MailObjectNotifyModel
                    {
                        objectAction = "creation",
                        objectType = "Role",
                        objectName = model.roleName,
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
                res.Data = true;
                return Ok(res);
            }

            res.Success = false;
            res.Data = false;
            return Ok(res);
        }

        /// <summary>
        /// method to fetch roles
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("getRoles")]
        public async Task<IActionResult> GetRoles([FromBody] PagedPostModel model) {
            ApiResponse<PagedData<IdentityRole>> res = new ApiResponse<PagedData<IdentityRole>>();
            var roles = await _roleManager.Roles.ToListAsync();            
            if(!String.IsNullOrEmpty(model.searchValue)){
                roles = roles.Where(u => u.Name!.ToLower().Contains(model.searchValue.ToLower())).ToList();
            }
            var pagedData = Pagination.PagedResult(roles, model.page, model.pageSize);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed all roles!");
            res.Success = true;
            res.Data = pagedData;
            return Ok(res);
        }

        /// <summary>
        /// method to delete a role
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("deleteRole")]
        public async Task<IActionResult> DeleteRoles([FromBody] RoleIdModel model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            var role = await _roleManager.FindByIdAsync(model.id);
            if(role==null) {
                res.Success = false;
                res.Data= false;
                res.Message = "Role with id " + model.id + " not found!";
                return Ok(res);
            } 
            var erg = await GetUserCountForRole(role.Name!);
            if(erg>0) {
                res.Success = false;
                res.Data= false;
                res.Message = "Role cannot deleted. Role has " + erg + " members!";
                return Ok(res);
            }
            
            await _roleManager.DeleteAsync(role);   
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " deleted role " + role.Name + "! ");   
            // notify admin
            if (_sett.Notif.SendNotifOnObjectDeletion == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Deletion",
                    objectType = "Role",
                    objectName = role.Name!,
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
            res.Data = true;
            return Ok(res);
        }

        /// <summary>
        /// count role members
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        private async Task<int> GetUserCountForRole(string roleName)
        {
            var Users = await _userManager.Users.Where(u=>u.RolesCombined!.ToLower().Contains(roleName.ToLower())).ToListAsync();
            return Users.Count();
        }
    }
}