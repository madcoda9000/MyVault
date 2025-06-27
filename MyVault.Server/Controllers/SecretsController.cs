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
using Mapster;
using Ganss.Xss;
using System.Text.Json;
using System.Security.Claims;
using MyVault.Shared.Models.Auth;

namespace MyVault.Server.Controllers
{
    /// <summary>
    /// secrets controller class
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class SecretsController : ControllerBase
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
        /// logger property
        /// </summary>
        private readonly ILogger<SecretsController> _logger;
        /// <summary>
        /// settings service property
        /// </summary>
        private readonly ISettingsService _sett;
        /// <summary>
        /// ermail service property
        /// </summary>
        private readonly IEmailSendService _mail;
        /// <summary>
        /// crypto service property
        /// </summary>
        private readonly IEncryptionServices _crypt;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="crypt"></param>
        /// <param name="mail"></param>
        /// <param name="sett"></param>
        /// <param name="us"></param>
        /// <param name="rol"></param>
        /// <param name="conf"></param>
        /// <param name="cont"></param>
        /// <param name="log"></param>
        public SecretsController(IEncryptionServices crypt, IEmailSendService mail, ISettingsService sett, UserManager<AppUser> us, RoleManager<IdentityRole> rol, IConfiguration conf, AppDbContext cont, ILogger<SecretsController> log)
        {
            _userManager = us;
            _roleManager = rol;
            _configuration = conf;
            _context = cont;
            _logger = log;
            _sett = sett;
            _mail = mail;
            _crypt = crypt;
        }

        #region "SECRET HISTORY"

        /// <summary>
        /// method to fetch secrets history
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSecretHistory")]
        public async Task<IActionResult> GetSecretHistory([FromBody] GetSecretModel model)
        {
            ApiResponse<List<SecretsHistory>> resp = new ApiResponse<List<SecretsHistory>>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                var lst = await _context.AppSecretsHistory!.ToListAsync();
                lst = lst.Where(sh => sh.S_Id == model.secretId).OrderByDescending(s => s.id).ToList();
                resp.Success = true;
                resp.Data = lst;
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Permission denied!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to fetch the description of a secret history entry
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSecretHistoryDescription")]
        public async Task<ActionResult> GetSecretHistoryDescription([FromBody] GetHistoryEntry model)
        {
            ApiResponse<string> resp = new ApiResponse<string>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecretsHistory!.FirstOrDefaultAsync(s => s.id == model.id);
            if (sec == null) { resp.Message = "No Secret found with id " + model.id; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                resp.Data = sec.S_Description;
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed description from history for secret " + sec.S_Name);
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to fetch the encrypted password for a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSecretHistoryPassword")]
        public async Task<ActionResult> GetSecretHistoryPassword([FromBody] GetHistoryEntry model)
        {
            ApiResponse<string> resp = new ApiResponse<string>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecretsHistory!.FirstOrDefaultAsync(s => s.id == model.id);
            if (sec == null) { resp.Message = "No Secret found with id " + model.id; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                resp.Data = _crypt.DecryptString(sec.S_Password!);
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " copied password from history for secret " + sec.S_Name + " to clipboard.");
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to fetch the encrypted username for a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSecretHistoryUsername")]
        public async Task<ActionResult> GetSecretHistoryUsername([FromBody] GetHistoryEntry model)
        {
            ApiResponse<string> resp = new ApiResponse<string>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecretsHistory!.FirstOrDefaultAsync(s => s.id == model.id);
            if (sec == null) { resp.Message = "No Secret found with id " + model.id; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                resp.Data = _crypt.DecryptString(sec.S_Username!);
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " copied username from history for secret " + sec.S_Name + " to clipboard.");
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }


        #endregion

        #region "SECRET METHODS"

        /// <summary>
        /// method to import a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("importSecret")]
        public async Task<IActionResult> ImportSecret([FromBody] NewSecretModel model) {
            ApiResponse<bool> resp = new ApiResponse<bool>();
            // create and save new secret
            Secrets sec = new Secrets();
            var sanitizer = new HtmlSanitizer();
            if (!String.IsNullOrEmpty(model.s_name)) { sec.S_Name = model.s_name; } else { sec.S_Name = ""; }
            if (!String.IsNullOrEmpty(model.s_username)) { sec.S_Username = _crypt.EncryptString(model.s_username!); } else { _crypt.EncryptString(""); }
            if (!String.IsNullOrEmpty(model.s_password)) { sec.S_Password = _crypt.EncryptString(model.s_password!); } else { _crypt.EncryptString(""); }
            if (!String.IsNullOrEmpty(model.s_url)) { sec.S_Url = model.s_url; } else { sec.S_Url = ""; }
            if (!String.IsNullOrEmpty(model.s_hostname)) { sec.S_HostName = model.s_hostname; } else { sec.S_HostName = ""; }
            if (!String.IsNullOrEmpty(model.s_url)) { sec.S_Url = model.s_url; } else { sec.S_Url = ""; }
            if (!String.IsNullOrEmpty(model.s_description) && model.s_description != "<p><br></p>") { sec.S_Description = sanitizer.Sanitize(model.s_description); } else { sec.S_Description = ""; }
            if (!String.IsNullOrEmpty(User.Identity!.Name!)) { sec.S_createdBy = User.Identity!.Name!; } else { sec.S_createdBy = ""; }
            if (!String.IsNullOrEmpty(model.s_userroles)) { sec.S_UserRoles = model.s_userroles; } else { sec.S_UserRoles = ""; }

            var srv = await _context.AppSecrets!.AddAsync(sec);
            await _context.SaveChangesAsync();

            // create a history object
            var histObj = new SecretsHistory();
            sec.Adapt(histObj);
            await _context.AppSecretsHistory!.AddAsync(histObj);
            await _context.SaveChangesAsync();
            _logger.LogInformation("created new History entry for secret " + sec.S_Name);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " imported new secret " + sec.S_Name);

            if (_sett.Notif.SendNotifOnObjectCreation == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "new secret imported",
                    objectType = "Secret",
                    objectName = sec.S_Name,
                    executedBy = User.Identity!.Name!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = _sett.Notif.NotificationReceiver;
                job.Subject = "GroupVault: " + cmod.objectType + " Object | " + cmod.objectAction;
                job.Template = "ObjectMail";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();                
            }

            resp.Success = true;
            resp.Data = true;
            return Ok(resp);

        }

        /// <summary>
        /// method to check if secret exists already
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("checkIfSecretExists")]
        public async Task<IActionResult> CheckIfSecretExists([FromBody] CheckIfSecretExistsModel model) {
            ApiResponse<bool> resp = new ApiResponse<bool>();
            var erg = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Name!.ToLower() == model.secretName.ToLower() && s.S_UserRoles.ToLower() == model.secretRole.ToLower());
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
        /// method to fetch an decrypted secret
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("getSecretsDecr")]
        public async Task<IActionResult> GetSecretsDecr()
        {
            ApiResponse<List<ExportSecretModel>> res = new ApiResponse<List<ExportSecretModel>>();
            var user = await GetCurrentUser();
            if (user == null)
            {
                res.Success = false;
                res.Data = null;
                res.Message = "Uauthorized! No user object.";
                return Ok(res);
            }
            else
            {

                if (user.RolesCombined!.ToLower().Contains("admin"))
                {
                    var erg = await _context.AppSecrets!.ToListAsync();
                    List<ExportSecretModel> exp = new List<ExportSecretModel>();
                    if (erg != null)
                    {
                        foreach (Secrets s in erg)
                        {
                            ExportSecretModel sec = new ExportSecretModel();
                            sec.S_Name = s.S_Name;
                            sec.S_HostName = s.S_HostName;
                            sec.S_Url = s.S_Url;
                            sec.S_Username = _crypt.DecryptString(s.S_Username);
                            sec.S_Password = _crypt.DecryptString(s.S_Password);
                            sec.S_Description = s.S_Description;
                            sec.S_UserRoles = s.S_UserRoles;
                            exp.Add(sec);
                        }
                        _logger.LogWarning("AUDIT: " + User.Identity!.Name + " export all secrets decrypted!");
                        
                        var cmod = new MailObjectNotifyModel
                        {
                            objectAction = "User exported all secrets decrypted!",
                            objectType = "Secret",
                            objectName = "all Secrets",
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

                        res.Success = true;
                        res.Data = exp;
                        return Ok(res);
                    }
                }
                else
                {
                    res.Success = false;
                    res.Data = null;
                    res.Message = "Uauthorized! No admin permissions .";
                    return Ok(res);
                }
            }
            res.Success = false;
            return Ok(res);
        }

        /// <summary>
        /// method to delete a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("deleteSecret")]
        public async Task<IActionResult> DeleteSecret([FromBody] GetSecretModel model) {
            ApiResponse<bool> resp = new ApiResponse<bool>();
            AppUser us = await GetCurrentUser();
            
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }
            var secToDel = sec.S_Name;

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }

            if(allowView) {
                // delete secret
                _context.AppSecrets!.Remove(sec);
                await _context.SaveChangesAsync();
                _logger.LogWarning("AUDIT: " + User.Identity!.Name + " deleted secret " + secToDel);

                // cleaup secret history
                var lst = await _context.AppSecretsHistory!.Where(s => s.S_Id == model.secretId).ToListAsync();
                if(lst.Count > 0) {
                    foreach(SecretsHistory s in lst) {
                        var secHistToDel = "Orig. Secret: " + secToDel + " | History entry: id: " + s.id + " - name: " + s.S_Name;
                        _context.Remove(s);
                        await _context.SaveChangesAsync();
                        _logger.LogWarning("AUDIT: " + User.Identity!.Name + " deleted secret history entry. " + secHistToDel);
                    }
                }
                if(_sett.Notif.SendNotifOnObjectDeletion==true) {
                    var cmod = new MailObjectNotifyModel
                        {
                            objectAction = "User deleted secret",
                            objectType = "Secret",
                            objectName = secToDel!,
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

                resp.Success = true;
                return Ok(resp);

            } else {
                resp.Success = false;
                resp.Data = false;
                resp.Message = "No permission to delete this secret!";
                return Ok(resp);
            }
         }

        /// <summary>
        /// method to get a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSecret")]
        public async Task<IActionResult> GetSecret([FromBody] GetSecretModel model)
        {
            ApiResponse<UpdateSecretModel> resp = new ApiResponse<UpdateSecretModel>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                UpdateSecretModel secc = new UpdateSecretModel();
                secc.s_Id = sec.S_Id;
                secc.s_name = sec.S_Name!;
                secc.s_description = sec.S_Description;
                secc.s_hostname = sec.S_HostName;
                secc.s_password = _crypt.DecryptString(sec.S_Password);
                secc.s_username = _crypt.DecryptString(sec.S_Username);
                secc.s_url = sec.S_Url;
                secc.s_userroles = sec.S_UserRoles;
                resp.Data = secc;
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " opened secret " + sec.S_Name + " in edit mode");
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to update a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("updateSecret")]
        public async Task<IActionResult> UpdateSecret([FromBody] UpdateSecretModel model)
        {
            ApiResponse<bool> res = new ApiResponse<bool>();

            AppUser us = await GetCurrentUser();

            // check if role exists
            var roleErg = await _roleManager.RoleExistsAsync(model.s_userroles);
            if (!roleErg)
            {
                res.Message = "Secret cannot updated for role " + model.s_userroles + "! The Role " + model.s_userroles + " does not exist!";
                res.Success = false;
                return Ok(res);
            }

            // check if user has permission to save a secret for the role
            if (us.RolesCombined!.ToLower().Contains("admin") == false)
            {
                if (!CheckIfUserHasRolePermission(model.s_userroles!).Result == true)
                {
                    res.Message = "You've no permission to update a secret for the role " + model.s_userroles + "!";
                    res.Success = false;
                    return Ok(res);
                }
            }

            // update the secret 
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id == model.s_Id);
            if (sec == null)
            {
                res.Success = false;
                res.Data = false;
                return Ok(res);
            }
            sec.S_Name = model.s_name;
            sec.S_HostName = model.s_hostname;
            sec.S_Url = model.s_url;
            sec.S_Username = _crypt.EncryptString(model.s_username);
            sec.S_Password = _crypt.EncryptString(model.s_password);
            var sanitizer = new HtmlSanitizer();
            sec.S_Description = sanitizer.Sanitize(model.s_description);
            sec.S_ModifiedOn = DateTime.Now;
            _context.AppSecrets!.Update(sec);
            await _context.SaveChangesAsync();
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " updated secret " + sec.S_Name);

            // create a history object
            var histObj = new SecretsHistory();
            sec.Adapt(histObj);
            await _context.AppSecretsHistory!.AddAsync(histObj);
            await _context.SaveChangesAsync();
            _logger.LogInformation("created new History entry for secret " + sec.S_Name);

            if (_sett.Notif.SendNotifOnObjectUpdate == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "modification",
                    objectType = "Secret",
                    objectName = sec.S_Name,
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
                //await _mail.sendMailAsync(_sett.Notif.NotificationReceiver, "GroupVault: " + cmod.objectType + " Object " + cmod.objectAction, "ObjectMail", cmod);
            }

            res.Success = true;
            res.Data = true;
            return Ok(res);
        }


        /// <summary>
        /// method to create a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("newSecret")]
        public async Task<IActionResult> NewSecret([FromBody] NewSecretModel model)
        {
            ApiResponse<bool> res = new ApiResponse<bool>();

            AppUser us = await GetCurrentUser();

            // check if secret exists already
            var secerg = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Name!.ToLower() == model.s_name.ToLower() && s.S_UserRoles.ToLower() == model.s_userroles.ToLower());
            if(secerg!=null) {
                res.Success = false;
                res.Message = "A secret with the name " + model.s_name + " for role " + model.s_userroles + " exists already!";
                return Ok(res);
            }

            // check if role exists
            var roleErg = await _roleManager.RoleExistsAsync(model.s_userroles);
            if (!roleErg)
            {
                res.Message = "Secret cannot created for role " + model.s_userroles + "! The Role " + model.s_userroles + " does not exist!";
                res.Success = false;
                return Ok(res);
            }

            // check if user has permission to save a secret for the role
            if (us.RolesCombined!.ToLower().Contains("admin") == false)
            {
                if (!CheckIfUserHasRolePermission(model.s_userroles!).Result == true)
                {
                    res.Message = "You've no permission to create a secret for the role " + model.s_userroles + "!";
                    res.Success = false;
                    return Ok(res);
                }
            }

            // create and save new secret
            Secrets sec = new Secrets();
            var sanitizer = new HtmlSanitizer();
            if (!String.IsNullOrEmpty(model.s_name)) { sec.S_Name = model.s_name; } else { sec.S_Name = ""; }
            if (!String.IsNullOrEmpty(model.s_username)) { sec.S_Username = _crypt.EncryptString(model.s_username!); } else { _crypt.EncryptString(""); }
            if (!String.IsNullOrEmpty(model.s_password)) { sec.S_Password = _crypt.EncryptString(model.s_password!); } else { _crypt.EncryptString(""); }
            if (!String.IsNullOrEmpty(model.s_url)) { sec.S_Url = model.s_url; } else { sec.S_Url = ""; }
            if (!String.IsNullOrEmpty(model.s_hostname)) { sec.S_HostName = model.s_hostname; } else { sec.S_HostName = ""; }
            if (!String.IsNullOrEmpty(model.s_url)) { sec.S_Url = model.s_url; } else { sec.S_Url = ""; }
            if (!String.IsNullOrEmpty(model.s_description) && model.s_description != "<p><br></p>") { sec.S_Description = sanitizer.Sanitize(model.s_description); } else { sec.S_Description = ""; }
            if (!String.IsNullOrEmpty(User.Identity!.Name!)) { sec.S_createdBy = User.Identity!.Name!; } else { sec.S_createdBy = ""; }
            if (!String.IsNullOrEmpty(model.s_userroles)) { sec.S_UserRoles = model.s_userroles; } else { sec.S_UserRoles = ""; }

            var srv = await _context.AppSecrets!.AddAsync(sec);
            await _context.SaveChangesAsync();

            // create a history object
            var histObj = new SecretsHistory();
            sec.Adapt(histObj);
            await _context.AppSecretsHistory!.AddAsync(histObj);
            await _context.SaveChangesAsync();
            _logger.LogInformation("created new History entry for secret " + sec.S_Name);
            _logger.LogInformation("AUDIT: " + User.Identity!.Name + " created new secret " + sec.S_Name);

            if (_sett.Notif.SendNotifOnObjectCreation == true)
            {
                var cmod = new MailObjectNotifyModel
                {
                    objectAction = "creation",
                    objectType = "Secret",
                    objectName = sec.S_Name,
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
        /// method to fetch a description for a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSecretDescription")]
        public async Task<ActionResult> GetSecretDescription([FromBody] GetSecretModel model)
        {
            ApiResponse<string> resp = new ApiResponse<string>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                resp.Data = sec.S_Description;
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed description for secret " + sec.S_Name);
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to fetch a decrypted secret by an given id
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getSingleSecretDecr")]
        public async Task<ActionResult> GetSingleSecretDecr([FromBody] GetSecretModel model)
        {
            ApiResponse<Secrets> resp = new ApiResponse<Secrets>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                sec.S_Password = _crypt.DecryptString(sec.S_Password!);
                sec.S_Username = _crypt.DecryptString(sec.S_Username!);
                resp.Data = sec;
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " viewed credentials for secret " + sec.S_Name);
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to fetch the encrypted password for a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getPassword")]
        public async Task<ActionResult> GetPassword([FromBody] GetSecretModel model)
        {
            ApiResponse<string> resp = new ApiResponse<string>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                resp.Data = _crypt.DecryptString(sec.S_Password!);
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " copied password for secret " + sec.S_Name + " to clipboard.");
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }

        /// <summary>
        /// method to fetch the encrypted username for a secret
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getUsername")]
        public async Task<ActionResult> GetUsername([FromBody] GetSecretModel model)
        {
            ApiResponse<string> resp = new ApiResponse<string>();
            AppUser us = await GetCurrentUser();
            var sec = await _context.AppSecrets!.FirstOrDefaultAsync(s => s.S_Id! == model.secretId);
            if (sec == null) { resp.Message = "No Secret found with id " + model.secretId; resp.Success = false; return Ok(resp); }

            Boolean allowView = false;
            // check if user has permission to secret
            if (us.RolesCombined!.ToLower().Contains("admin") ||
                us.RolesCombined!.ToLower().Contains(sec.S_UserRoles!.ToLower()))
            {
                allowView = true;
            }
            if (us.RolesCombined!.ToLower().Contains("user") && sec.S_UserRoles!.ToLower() == "user")
            {
                allowView = true;
            }
            if (allowView)
            {
                resp.Success = true;
                resp.Data = _crypt.DecryptString(sec.S_Username!);
                _logger.LogInformation("AUDIT: " + User.Identity!.Name + " copied username for secret " + sec.S_Name + " to clipboard.");
                return Ok(resp);
            }
            else
            {
                resp.Success = false;
                resp.Message = "Not Authorized!";
                return Ok(resp);
            }
        }


        #endregion

        #region "ROLES" 

        /// <summary>
        /// get roles for user
        /// </summary>
        /// <returns></returns>
        [Authorize]
        [HttpPost]
        [Route("getRolesForUser")]
        public async Task<IActionResult> GetRolesForUser()
        {
            var checkErg1 = await GetCurrentUser();
            ApiResponse<IEnumerable<IdentityRole>> resp = new ApiResponse<IEnumerable<IdentityRole>>();

            if (checkErg1 != null)
            {
                AppUser us = checkErg1;
                // if user is admin, filter admin and user role
                if (us.RolesCombined!.ToLower().Contains("admin"))
                {
                    IEnumerable<IdentityRole> lst = _roleManager.Roles.ToList().Where(r => r.Name!.ToLower() != "admin" && r.Name.ToLower() != "user");
                    resp.Data = lst;
                    resp.Success = true;
                    return Ok(resp);
                    // is user is in user role, return only user role
                }
                else if (us.RolesCombined!.ToLower().Contains("user"))
                {
                    IEnumerable<IdentityRole> lst = _roleManager.Roles.ToList().Where(r => r.Name!.ToLower() == "user");
                    resp.Data = lst;
                    resp.Success = true;
                    return Ok(resp);
                    // else return all roles assigned to the user
                }
                else
                {
                    String[] rls = us.RolesCombined.Split(",");
                    List<IdentityRole> lst = new List<IdentityRole>();
                    for (int i = 0; i < rls.Count(); i++)
                    {
                        var checkErg3 = await _roleManager.FindByNameAsync(rls[i]);
                        if (checkErg3 != null)
                        {
                            lst.Add(checkErg3);
                        }
                    }
                    resp.Data = lst;
                    resp.Success = true;
                    return Ok(resp);
                }
            }
            else
            {
                throw new Exception("Cannot get current user context!");
            }
        }

        #endregion

        #region "PAGED SECRET LISTS"

        /// <summary>
        /// action for view secrets
        /// </summary>
        /// <returns>the view</returns>
        [Authorize]
        [HttpPost]
        [Route("getSecretsPaged")]
        public async Task<IActionResult> GetSecretsPaged([FromBody] PagedSecretsModel model)
        {
            IEnumerable<Secrets> lst;
            ApiResponse<PagedData<Secrets>> resp = new ApiResponse<PagedData<Secrets>>();
            var checkErg1 = await GetCurrentUser();
            Console.WriteLine("USER:" + User.Identity);

            try
            {
                
                if (checkErg1 != null)
                {
                    AppUser us = checkErg1;
                    
                    // if user is admin and no role is selected, show all secrets
                    if (us.RolesCombined!.ToLower().Contains("admin") && String.IsNullOrEmpty(model.roleName) == true)
                    {
                        lst = _context.AppSecrets!.ToList().OrderByDescending(s => s.S_Id);
                        if (!String.IsNullOrEmpty(model.searchValue))
                        {
                            lst = lst.ToList().Where(m => (m.S_Name!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Description!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Url!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_HostName!.ToLower().Contains(model.searchValue.ToLower()))).ToList();
                        }
                        var pagedData = Pagination.PagedResult(lst, model.pageNumber, model.pageSize);
                        resp.Data = pagedData;
                        resp.Success = true;
                        return Ok(resp);
                    }
                    // if user is admin, and specific role is selected
                    else if (us.RolesCombined!.ToLower().Contains("admin") && String.IsNullOrEmpty(model.roleName) == false)
                    {
                        if (model.roleName.ToLower() == "all")
                        {
                            lst = _context.AppSecrets!.ToList().OrderByDescending(s => s.S_Id);
                        }
                        else
                        {
                            lst = _context.AppSecrets!.ToList().OrderByDescending(s => s.S_Id).Where(s => s.S_UserRoles!.ToLower() == model.roleName.ToLower());
                        }
                        if (!String.IsNullOrEmpty(model.searchValue))
                        {
                            lst = lst.ToList().Where(m => (m.S_Name!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Description!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Url!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_HostName!.ToLower().Contains(model.searchValue.ToLower()))).ToList();

                            //lst = lst.ToList().Where(m => m.S_Description!.ToLower().Contains(model.searchValue.ToLower()) ).ToList();
                        }
                        if (lst?.Any() != true)
                        {
                            var PagedData = new PagedData<Secrets>();
                            PagedData.TotalItemsCount = 0;
                            PagedData.TotalPages = 0;
                            resp.Data = PagedData;
                        }
                        else
                        {
                            var pagedData = Pagination.PagedResult(lst, model.pageNumber, model.pageSize);
                            resp.Data = pagedData;
                        }
                        resp.Success = true;
                        return Ok(resp);
                    }
                    // if user is in user role, show only secrets created by user and assigned to role user
                    else if (us.RolesCombined!.ToLower().Contains("user"))
                    {
                        lst = _context.AppSecrets!.ToList().OrderByDescending(s => s.S_Id).Where(s => s.S_createdBy!.ToLower() == us.UserName!.ToLower() && s.S_UserRoles!.ToLower() == "user");
                        if (!String.IsNullOrEmpty(model.searchValue))
                        {
                            lst = lst.ToList().Where(m => (m.S_Name!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Description!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Url!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_HostName!.ToLower().Contains(model.searchValue.ToLower()))).ToList();
                        }
                        var pagedData = Pagination.PagedResult(lst, model.pageNumber, model.pageSize);
                        resp.Data = pagedData;
                        resp.Success = true;
                        return Ok(resp);
                    }
                    // if user is no admin but a member of selcted role, return secrets for selected role
                    else if (String.IsNullOrEmpty(model.roleName) == false && us.RolesCombined!.ToLower().Contains(model.roleName.ToLower()))
                    {
                        lst = _context.AppSecrets!.ToList().OrderByDescending(s => s.S_Id).Where(s => s.S_UserRoles!.ToLower() == model.roleName.ToLower());
                        if (!String.IsNullOrEmpty(model.searchValue))
                        {
                            lst = lst.ToList().Where(m => (m.S_Name!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Description!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_Url!.ToLower().Contains(model.searchValue.ToLower()))
                            || (m.S_HostName!.ToLower().Contains(model.searchValue.ToLower()))).ToList();
                        }
                        var pagedData = Pagination.PagedResult(lst, model.pageNumber, model.pageSize);
                        resp.Data = pagedData;
                        resp.Success = true;
                        return Ok(resp);
                    }
                    // else return empty list
                    else
                    {
                        ApiResponse<List<Secrets>> errResp = new ApiResponse<List<Secrets>>();
                        errResp.Data = new List<Secrets>();
                        errResp.Success = false;
                        errResp.Message = "No permission rule match!";
                        return Ok(errResp);
                    }
                }
                else
                {
                    throw new Exception("Cannot get current user context!");
                }
            }
            catch (Exception ex)
            {
                ApiResponse<PagedData<Secrets>> respErr = new ApiResponse<PagedData<Secrets>>();
                respErr.Success = false;
                respErr.Message = ex.InnerException!.ToString();
                return Ok(respErr);
            }
        }

        #endregion

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
            var lst = User!.Identities.First().Claims.ToList();
            var name = lst?.FirstOrDefault(x => x.Type.Equals("username", StringComparison.OrdinalIgnoreCase))?.Value;
            var unamer = name != null ? name : "";
            var us = await _userManager.FindByNameAsync(unamer);
            return us!;
        }

        #endregion

    }
}