using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Server.Models.BusinessModels;
using MyVault.Shared.Models.Identity;
using MyVault.Shared.Models.FormModels;
using System.Reflection;
using MyVault.Server.Services;
using MyVault.Shared.Models.DataModels;
using System.Text.Json;
using MyVault.Shared.Models.Auth;

namespace MyVault.Server.Controllers
{
    /// <summary>
    /// model class for user
    /// </summary>
    public class UserIdModel {
        /// <summary>
        /// userid property
        /// </summary>
       public string id {get;set;}=string.Empty; 
    }   

    /// <summary>
    /// user controller class
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UsersController : ControllerBase
    {
        /// <summary>
        /// usermanager property
        /// </summary>
        private readonly UserManager<AppUser> _userManager;
        /// <summary>
        /// rolemanger property
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
        /// logger property
        /// </summary>
        private readonly ILogger<SettingsController> _logger;
        /// <summary>
        /// settings service property
        /// </summary>
        private readonly ISettingsService _sett;
        /// <summary>
        /// email service proeprty
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
        public UsersController(IEmailSendService mail, ISettingsService sett, UserManager<AppUser> us, RoleManager<IdentityRole> rol, IConfiguration conf, AppDbContext cont, ILogger<SettingsController> log) {
            _userManager = us;
            _roleManager = rol;
            _configuration = conf;
            _context = cont;
            _logger = log;
            _sett = sett;
            _mail = mail;
        }

        /// <summary>
        /// method to delete a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("deleteUser")]
        public async Task<IActionResult> DeleteUser([FromBody] UserIdModel model) {
            ApiResponse<Boolean> res = new ApiResponse<Boolean>();
            var user = await _userManager.FindByIdAsync(model.id);            
            if(user==null) {
                res.Success = false;
                res.Data = false;
                return Ok(res);
            } else {
                var usname = user.UserName;
                var erg = await _userManager.DeleteAsync(user);
                if(erg.Succeeded) {
                    res.Success = true;
                    res.Data = true;
                    // notify admin
                    if (_sett.Notif.SendNotifOnObjectDeletion == true)
                    {
                        var cmod = new MailObjectNotifyModel
                        {
                            objectAction = "Deletion",
                            objectType = "User",
                            objectName = usname!,
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
                    _logger.LogInformation("AUDIT: " + User.Identity!.Name + " deleted user " + user.UserName + "! ");
                    return Ok(res);
                } else {
                    res.Success = false;
                    foreach(var err in erg.Errors) {
                        res.Message += err.Description + "\n";
                    }
                    
                    return Ok(res);
                }
            }
        }

        /// <summary>
        /// method to create a new user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("createNewUser")]
        public async Task<IActionResult> CreateNewUser([FromBody] NewUserModel model) {
            ApiResponse<Boolean> res = new ApiResponse<Boolean>();

            if(model.nRoles.Length<=0) {
                res.Success = false;
                res.Message = "User must belong to one role at least!";
                return Ok(res);
            }

            AppUser us = new() {
            UserName = model.nName,
            Email = model.nEmail,
            EmailConfirmed = true,            
            SecurityStamp = Guid.NewGuid().ToString(),            
            };
            var result = await _userManager.CreateAsync(us, model.nPasswd);

            if(!result.Succeeded) {
                res.Success = false; 
                foreach(var err in result.Errors) {
                    res.Message += err.Description + "\n";
                }
                return Ok(res);
            }

            
            var nUser = await _userManager.FindByEmailAsync(model.nEmail!);
            var rls = model.nRoles.Split(',');
            foreach(var rl in rls) {
                await _userManager.AddToRoleAsync(nUser!, rl);
            }
            nUser!.IsLdapLogin = model.nLdap;
            nUser.IsMfaForce = model.nEnforceMfa;
            nUser.RolesCombined = model.nRoles;
            nUser.IsEnabled = true;
            nUser.LockoutEnabled = false;
            nUser.LastName = model.nLastName;
            nUser.FirstName = model.nFirstName;
            await _userManager.UpdateAsync(nUser);

            res.Success = true;

            // notify user about new account
            if(nUser.IsLdapLogin==true && _sett.Notif.SendWelcomeMailOnUserCreation==true) {
                var cmod1 = new MailConfirmModel{
                    url = _configuration["Client:url"] + "/Login",
                    name = nUser.UserName!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = nUser.Email!;
                job.Subject = "GroupVault: Welcome to GroupVault";
                job.Template = "WelcomeCreateLdap";
                job.objectModel = JsonSerializer.Serialize(cmod1);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();
            } else if(nUser.IsLdapLogin==false && _sett.Notif.SendWelcomeMailOnUserCreation==true) {
                var cmod2 = new MailConfirmModel{
                    url = _configuration["Client:url"] + "/Login",
                    name = nUser.UserName!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = nUser.Email!;
                job.Subject = "GroupVault: Welcome to GroupVault";
                job.Template = "WelcomeCreate";
                job.objectModel = JsonSerializer.Serialize(cmod2);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();
            }

            // notify admin
            if (_sett.Notif.SendNotifOnObjectCreation == true)
            {
                var cmod3 = new MailObjectNotifyModel
                {
                    objectAction = "Creation",
                    objectType = "User",
                    objectName = nUser.UserName!,
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod3.objectType + " Object " + cmod3.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod3);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " created user " + nUser.UserName + "! ");
            return Ok(res);
        }

        /// <summary>
        /// method to upadte user data
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("updateUserData")]
        public async Task<IActionResult> UpdateUserData([FromBody] UpdateUserDataModel model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            var message = "";
            var user = await _userManager.FindByIdAsync(model.userId);
            if(user!=null) {
                user.FirstName = model.fName;
                user.LastName = model.lName;
                user.Email = model.email;
                var erg = await _userManager.UpdateAsync(user);
                if(erg.Succeeded) {
                    // notify admin
                    if (_sett.Notif.SendNotifOnObjectUpdate == true)
                    {
                        var cmod = new MailObjectNotifyModel
                        {
                            objectAction = "Updated User data",
                            objectType = "User",
                            objectName = user.UserName!,
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
                } else {
                    foreach(var err in erg.Errors) {
                        message += err.Description + "\n";
                        }
                }
            } else {    
                message = "User with id " + model.userId + " not found!";
            }

            res.Success = false;
            res.Data = false;
            res.Message = message;
            return Ok(res);
        }

        /// <summary>
        /// method to change a users password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("changePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model) {
            ApiResponse<bool> res = new ApiResponse<bool>();
            var message = "";
            var user = await _userManager.FindByIdAsync(model.userId);
            if(user!=null) {
                var result = await _userManager.CheckPasswordAsync(user, model.oldPw);
                if(result==true) {
                    var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var pwResetResult = await _userManager.ResetPasswordAsync(user, passwordResetToken, model.newPw);
                    if(pwResetResult.Succeeded) {
                        // notify admin
                        if (_sett.Notif.SendNotifOnObjectUpdate == true)
                        {
                            var cmod = new MailObjectNotifyModel
                            {
                                objectAction = "Password change",
                                objectType = "User",
                                objectName = user.UserName!,
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
                    } else {
                        foreach(var err in pwResetResult.Errors) {
                        message += err.Description + "\n";
                        }
                    }
                } else {
                    message = "Your current password is not correct!";
                }
            } else {
                message = "User with id " + model.userId + " not found!";
            }
            res.Success = false;
            res.Data = false;
            res.Message = message;
            return Ok(res);
        }

        /// <summary>
        /// method to update a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("updateUser")]
        public async Task<IActionResult> UpdateUser([FromBody] UpdateUserModel model) {
            ApiResponse<AppUser> res = new ApiResponse<AppUser>();
            var user = await _userManager.FindByIdAsync(model.uId);
            if(user==null) {
                res.Success = false;
                res.Message = "User with id " + model.uId + "not found!";
            }

            // check if we have to change the password
            if(!String.IsNullOrEmpty(model.uPasswd) && user != null) {
                var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = await _userManager.ResetPasswordAsync(user, passwordResetToken, model.uPasswd);
                if(!result.Succeeded) {
                    res.Success = false; 
                    foreach(var err in result.Errors) {
                        res.Message += err.Description + "\n";
                    }
                    return Ok(res);
                }
            }

            if(model.uName != user!.UserName) {user!.UserName = model.uName;}
            if(model.uEmail != user!.Email) {user!.Email = model.uEmail;}
            user!.IsLdapLogin = model.uLdap;
            user!.IsMfaForce = model.uEnforceMfa;
            user!.LastName = model.uLastName;
            user!.FirstName = model.uFirstName;

            await _userManager.UpdateAsync(user!);

            var userRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user!, userRoles.ToArray());
            await _userManager.UpdateAsync(user);
            var newRls = model.uRoles.Split(',');
            foreach(var rl in newRls) {
                var rol = await _roleManager.FindByNameAsync(rl);
                if(rol!=null) {
                    await _userManager.AddToRoleAsync(user!, rol.Name!);
                }
            }
            user.RolesCombined = model.uRoles;
            await _userManager.UpdateAsync(user!);

            res.Success = true;
            res.Data = user!;
            // notify admin
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Modification",
                    objectType = "User",
                    objectName = user.UserName,
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
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " modified user " + user!.UserName + "! ");
            return Ok(res);
        }

        /// <summary>
        /// disable ldap for user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("disableLdapForUser")]
        public async Task<IActionResult> DisableLdapForUser([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.IsLdapLogin = false;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " disabled ldap for user " + res.UserName + "! ");
            ApiResponse<Boolean> erg = new ApiResponse<bool>();
            erg.Success = true;
            erg.Data = true;
            // notify admin
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Disabled LDAP",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(erg);
        }

        /// <summary>
        /// enable ldap for user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("enableLdapForUser")]
        public async Task<IActionResult> EnableLdapForUser([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.IsLdapLogin = true;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " enabled ldap for user " + res.UserName + "! ");
            ApiResponse<Boolean> erg = new ApiResponse<bool>();
            erg.Success = true;
            erg.Data = true;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Enabled LDAP",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(erg);
        }

        /// <summary>
        /// unlock a user account
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("unlockUser")]
        public async Task<IActionResult> UnlockUser([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.LockoutEnabled = false;
            res.AccessFailedCount = 0;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " unlocked user " + res.UserName + "! ");
            ApiResponse<Boolean> erg = new ApiResponse<bool>();
            erg.Success = true;
            erg.Data = true;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Unlock User account",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(erg);
        }

        /// <summary>
        /// lock a user account
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("lockUser")]
        public async Task<IActionResult> LockUser([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.LockoutEnabled = true;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " locked user " + res.UserName + "! ");
            ApiResponse<Boolean> erg = new ApiResponse<bool>();
            erg.Success = true;
            erg.Data = true;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Locked User account",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(erg);
        }

        /// <summary>
        /// disable mfa for a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("disableMfa")]
        public async Task<IActionResult> DisableMfa([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.TwoFactorEnabled = false;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " disabled MFA for user " + res.UserName + "! ");
            ApiResponse<Boolean> erg = new ApiResponse<bool>();
            erg.Success = true;
            erg.Data = true;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Disabled MFA",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(erg);
        }

        /// <summary>
        /// disable mfa for a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("enableMfa")]
        public async Task<IActionResult> EnableMfa([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " enabled MFA for user " + res.UserName + "! ");
            ApiResponse<Boolean> erg = new ApiResponse<bool>();
            erg.Success = true;
            erg.Data = true;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Enabled MFA",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(erg);
        }

        /// <summary>
        /// fetch users
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("getUsers")]
        public async Task<IActionResult> GetUsers([FromBody] PagedPostModel model) {
            var res = await _userManager.Users.ToListAsync();
            if(!string.IsNullOrEmpty(model.searchValue)) {
                res = res.Where(u => u.UserName!.ToLower().Contains(model.searchValue.ToLower())).ToList();
            }
            ApiResponse<PagedData<AppUser>> response = new ApiResponse<PagedData<AppUser>>();
            var pagedData = Pagination.PagedResult(res, model.page, model.pageSize);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed all users page! ");
            response.Success = true;
            response.Data = pagedData;
            return Ok(response);
        }

        /// <summary>
        /// get a single user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getUser")]
        public async Task<IActionResult> GetUser([FromBody] UserIdModel model) {
            ApiResponse<AppUser> response = new ApiResponse<AppUser>();
            var res = await _userManager.FindByIdAsync(model.id);
            if(res!=null) {
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed user detail for user " + res.UserName + "! ");            
                response.Success = true;
                response.Data = res;
                return Ok(response);
            } else {
                response.Success = false;
                response.Data = null;
                response.Message = "User with id " + model.id + " not found!";
                return Ok(response);
            }            
        }

        /// <summary>
        /// enable mfa enforcement for a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("enableMfaEnforce")]
        public async Task<IActionResult> EnableMfaEnforce([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.IsMfaForce = true;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " enabled MFA enforcement for user " + res.UserName + "! ");
            ApiResponse<AppUser> response = new ApiResponse<AppUser>();
            response.Success = true;
            response.Data = res;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Enforced MFA for User",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(response);
        }

        /// <summary>
        /// disable mfa enforcement for a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles ="Admin")]
        [HttpPost]
        [Route("disableMfaEnforce")]
        public async Task<IActionResult> DisableMfaEnforce([FromBody] UserIdModel model) {
            var res = await _userManager.FindByIdAsync(model.id);
            res!.IsMfaForce = false;
            await _userManager.UpdateAsync(res);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " disabled MFA enforcement for user " + res.UserName + "! ");
            ApiResponse<AppUser> response = new ApiResponse<AppUser>();
            response.Success = true;
            response.Data = res;
            // notify admin
            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "Disable MFA Enforcement",
                    objectType = "User",
                    objectName = res.UserName!,
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
            return Ok(response);
        }
    }
}