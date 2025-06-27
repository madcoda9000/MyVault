using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyVault.Server.Data;
using MyVault.Server.Helper;
using MyVault.Shared.Models.DataModels;
using MyVault.Shared.Models.Identity;
using MyVault.Server.Services;
using MyVault.Shared.Models.Auth;
using MyVault.Shared.Models.FormModels;
using Novell.Directory.Ldap;
using OtpNet;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MyVault.Server.Controllers
{
    /// <summary>
    /// AuthenticateController class
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
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
        /// iconfiiguration property
        /// </summary>
        private readonly IConfiguration _configuration;
        /// <summary>
        /// ilogger property
        /// </summary>
        private readonly ILogger<AuthenticateController> _logger;
        /// <summary>
        /// IEmailSendService property
        /// </summary>
        private readonly IEmailSendService _mail;
        /// <summary>
        /// dbcontext property
        /// </summary>
        private readonly AppDbContext _context;
        /// <summary>
        /// settings service property
        /// </summary>
        private readonly ISettingsService _sett;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="userManager"></param>
        /// <param name="roleManager"></param>
        /// <param name="configuration"></param>
        /// <param name="log"></param>
        /// <param name="mail"></param>
        /// <param name="sett"></param>
        /// <param name="context"></param>
        public AuthenticateController(
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ILogger<AuthenticateController> log,
            IEmailSendService mail,
            ISettingsService sett,
            AppDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _logger = log;
            _mail = mail;
            _sett = sett;
            _context = context;
        }

        /// <summary>
        /// method to verify a mfa token
        /// </summary>
        /// <param name="model"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/verifyMfaAuth
        ///     {        
        ///       "mfaToken": "3254lkhn235iu43g6",
        ///       "userId": "65498665446"
        ///     }
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type bool</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpPost("verifyMfaAuth")]
        [Authorize]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
        public async Task<IActionResult> VerifyMfaAuth([FromBody] MfaVerifyTokenModel model)
        {
            ApiResponse<bool> res = new ApiResponse<bool>();
            var usr = await _userManager.FindByIdAsync(model.userId);
            if (usr != null)
            {
                if (usr.TwoFactorAuthToken == model.mfaToken)
                {
                    res.Success = true;
                    res.Data = true;
                    return Ok(res);
                }
                else
                {
                    res.Success = false;
                    res.Data = false;
                    res.Message = "MFA token could not be verified!";
                    _logger.LogError("AUDIT: " + usr.UserName + " 2fa token verification failed! ");
                    return Ok(res);
                }
            }
            res.Success = false;
            res.Data = false;
            res.Message = "MFA token could not be verified!";
            return Ok(res);
        }

        /// <summary>
        /// method to verify a otp token
        /// </summary>
        /// <param name="model"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/authMfa
        ///     {        
        ///       "userId": "524646464654",
        ///       "otp": "3254lkhn235iu43g6"
        ///     }
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type string</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpPost("authMfa")]
        [Authorize]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<string>), StatusCodes.Status200OK)]
        public async Task<IActionResult> AuthMfa([FromBody] MfaAuthModel model)
        {
            ApiResponse<string> res = new ApiResponse<string>();
            var usr = await _userManager.FindByIdAsync(model.userId);
            if (usr != null)
            {
                var totp = new Totp(Base32Encoding.ToBytes(usr.TwoFactorSecret), totpSize: 6);
                var totpCode = totp.ComputeTotp();
                if (totpCode == model.otp)
                {
                    usr.TwoFactorAuthToken = Guid.NewGuid().ToString();
                    await _userManager.UpdateAsync(usr);
                    res.Success = true;
                    res.Data = usr.TwoFactorAuthToken;
                    _logger.LogInformation("AUDIT: " + usr.UserName + " 2fa code verified successfully! ");
                    return Ok(res);
                }
                else
                {
                    res.Success = false;
                    res.Data = string.Empty;
                    res.Message = "Wrong OTP code!";
                    _logger.LogError("AUDIT: " + usr.UserName + " 2fa code verification failed! ");
                    return Ok(res);
                }
            }
            res.Success = false;
            res.Data = string.Empty;
            return Ok(res);
        }

        /// <summary>
        /// method to setup mfa configuration for a user
        /// </summary>
        /// <param name="model"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/setMfaSetup
        ///     {        
        ///       "key": "524646464654",
        ///       "url": "opt://",
        ///       "otp": "3254lkhn235iu43g6",
        ///       "userId": "5454635435453"
        ///     }
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type string</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpPost("setMfaSetup")]
        [Authorize]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<string>), StatusCodes.Status200OK)]
        public async Task<IActionResult> SetMfaSetup([FromBody] MfaSetupModel model)
        {
            ApiResponse<string> res = new ApiResponse<string>();
            var usr = await _userManager.FindByIdAsync(model.userId);
            if (usr != null)
            {
                var totp = new Totp(Base32Encoding.ToBytes(model.key), totpSize: 6);
                var totpCode = totp.ComputeTotp();
                if (model.otp == totpCode!)
                {
                    usr.TwoFactorSecret = model.key;
                    usr.TwoFactorEnabled = true;
                    usr.IsMfaForce = false;
                    usr.TwoFactorAuthToken = Guid.NewGuid().ToString();
                    await _userManager.UpdateAsync(usr);
                    res.Success = true;
                    res.Data = usr.TwoFactorAuthToken;
                    _logger.LogInformation("AUDIT: " + usr.UserName + " completed 2fa setup! ");
                    return Ok(res);
                }
                else
                {
                    res.Success = false;
                    res.Message = "Wrong code!";
                    res.Data = string.Empty;
                    return Ok(res);
                }

            }
            res.Success = false;
            res.Data = string.Empty;
            return Ok(res);
        }

        /// <summary>
        /// method to retrieve initial mfa setup for a user
        /// </summary>
        /// <param name="userId"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     GET api/Authentication/getMfaSetup?userId=654646465476465
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type MfaSetupModel</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpGet("getMfaSetup")]
        [Authorize]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<MfaSetupModel>), StatusCodes.Status200OK)]
        public async Task<IActionResult> GetMfaSetup(string userId)
        {
            ApiResponse<MfaSetupModel> res = new ApiResponse<MfaSetupModel>();
            var usr = await _userManager.FindByIdAsync(userId);
            if (userId != null)
            {
                var key = KeyGeneration.GenerateRandomKey(20);
                var base32String = Base32Encoding.ToString(key);
                var uriString = new OtpUri(OtpType.Totp, base32String, usr!.Email, _sett.Brand.ApplicationName).ToString();
                MfaSetupModel set = new MfaSetupModel
                {
                    key = base32String,
                    url = uriString,
                    userId = usr.Id
                };
                res.Data = set;
                res.Success = true;
                _logger.LogInformation("AUDIT: " + usr.UserName + " started 2faa setup... ");
                return Ok(res);
            }
            res.Success = false;
            res.Data = new MfaSetupModel();
            return Ok(res);
        }

        /// <summary>
        /// method to authenticate a user
        /// </summary>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/login
        ///     {        
        ///       "username": "user.name",
        ///       "password": "s#f+äds5643zt"      
        ///     }
        /// </remarks>
        /// <param name="model"></param>
        /// <returns>a json object of type ApiResponse</returns>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type TokenResponse</response>
        [HttpPost("login")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<TokenResponse>), StatusCodes.Status200OK)]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            TokenResponse tks = new TokenResponse();
            ApiResponse<TokenResponse> res = new ApiResponse<TokenResponse>();
            var user = await _userManager.FindByNameAsync(model.Username!);
            if (user != null)
            {
                var result = false;
                var logonType = "DATABASE";
                if (user.IsLdapLogin == true)
                {
                    result = this.makeLDAPAuth(user, model.Password!);
                    logonType = "LDAP";
                }
                else
                {
                    result = await _userManager.CheckPasswordAsync(user, model.Password!);
                }


                if (user.LockoutEnabled == true)
                {
                    res.Success = false;
                    res.Message = "Your account is locked currently! Please contact your adminsitrator.";
                    _logger.LogWarning("AUDIT: " + model.Username + " logon try. Account locked! ");
                    return Ok(res);
                }
                else if (!result && user.AccessFailedCount >= 3)
                {
                    user.LockoutEnabled = true;
                    await _userManager.UpdateAsync(user);
                    res.Success = false;
                    _logger.LogWarning("AUDIT: " + model.Username + " account locked due too many failed login trys! ");
                    res.Message = "Your account is locked due too many falied logins! Please contact your administrator.";
                    return Ok(res);
                }
                else if (!result)
                {
                    user.AccessFailedCount = user.AccessFailedCount + 1;
                    await _userManager.UpdateAsync(user);
                    res.Success = false;
                    res.Message = "Wrong credentials!";
                    _logger.LogWarning("AUDIT: " + model.Username + " logon failed! Wrong credential. Increased Failedlogon count.");
                    return Ok(res);
                }

                user.AccessFailedCount = 0;
                await _userManager.UpdateAsync(user);
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Name, user.UserName!),
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                    new Claim(ClaimTypes.Email, user.Email!),
                    new Claim(ClaimTypes.Sid, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };


                if (userRoles != null)
                {
                    var rlsComb = "";
                    if (userRoles.Count() > 0 && userRoles.Count() <= 1)
                    {
                        rlsComb = userRoles[0].ToString();
                    }
                    else
                    {
                        for (int i = 0; i < userRoles.Count; i++)
                        {
                            if (i + 1 != userRoles.Count) { rlsComb += userRoles[i] + ","; }
                            else { rlsComb += userRoles[i]; }
                        }
                    }
                    if (rlsComb.Length > 0)
                    {
                        var rolesCombinedClaim = new Claim(JwtRegisteredClaimNames.Amr, rlsComb);
                        authClaims.Add(rolesCombinedClaim);
                    }

                    foreach (var userRole in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                    }
                }

                if(user.TwoFactorAuthToken!=null) {
                    var mfaTokenClaim = new Claim("mfaAuthToken", user.TwoFactorAuthToken.ToString());
                    authClaims.Add(mfaTokenClaim);
                }  

                var mfaClaim = new Claim("mfaEnabled", user.TwoFactorEnabled.ToString());
                authClaims.Add(mfaClaim);

                var mfaEnfClaim = new Claim("mfaEnforced", user.IsMfaForce.ToString());
                authClaims.Add(mfaEnfClaim);

                var rolesClaim = new Claim("rlsComb", user.RolesCombined!);
                authClaims.Add(rolesClaim);

                var usernameClaim = new Claim("username", user.UserName!);
                authClaims.Add(usernameClaim);

                var firstnameClaim = new Claim("firstname", user.FirstName!);
                authClaims.Add(firstnameClaim);

                var lastnameClaim = new Claim("lastname", user.LastName!);
                authClaims.Add(lastnameClaim);


                var token = CreateToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                string crefreshTokenValidityInDays = Environment.GetEnvironmentVariable("G_RFRESHTOKENVALIDITYINDAYS") ?? _configuration["JWT:RefreshTokenValidityInDays"]!;

                _ = int.TryParse(crefreshTokenValidityInDays, out int refreshTokenValidityInDays);

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                await _userManager.UpdateAsync(user);

                tks.refresh_token = refreshToken;
                tks.access_token = new JwtSecurityTokenHandler().WriteToken(token);
                res.Data = tks;
                res.Success = true;

                Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Expires = DateTime.UtcNow.AddDays(1),
                    Path = "/"
                });
                Response.Cookies.Append("accessToken", tks.access_token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Expires = DateTime.UtcNow.AddHours(1),
                    Path = "/"
                });

                _logger.LogInformation("AUDIT: " + user.UserName + " " + logonType + " login successful! ");
                return Ok(res);
            }
            res.Success = false;
            res.Message = "Wrong credentials!";
            _logger.LogWarning("AUDIT: " + model.Username + " logon fail! Wrong credentials. ");
            return Ok(res);
        }

        /// <summary>
        /// Method to delete all cookies from client and tokens from user object
        /// </summary>
        /// <returns></returns>
        [HttpPost("logout")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var username = User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return Unauthorized();

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return Unauthorized();

            // RefreshToken zurücksetzen
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = DateTime.MinValue; 
            await _userManager.UpdateAsync(user);

            // Cookies löschen (leeren + abgelaufen setzen)
            var expiredCookie = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(-1) // abgelaufen
            };

            Response.Cookies.Append("refreshToken", "", expiredCookie);
            Response.Cookies.Append("accessToken", "", expiredCookie);

            _logger.LogInformation("AUDIT: " + username + " successfully logged out.");

            return Ok(new ApiResponse<bool>
            {
                Success = true,
                Data = true,
                Message = "Logout successful."
            });
        }


        /// <summary>
        /// method for self register a account
        /// </summary>
        /// <param name="model"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/register
        ///     {
        ///         "username": "string",
        ///         "email": "user@example.com",
        ///         "password": "string"
        ///     }
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type bool</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpPost("register")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username!);
            if (userExists != null)
            {
                _logger.LogWarning("AUDIT: Register new user failed. User already exists! ");
                return Ok(new ApiResponse<bool> { Success = false, Message = "User already exists!", Data = false });
            }

            userExists = await _userManager.FindByEmailAsync(model.Email!);
            if (userExists != null)
            {
                _logger.LogWarning("AUDIT: Register new user failed. User with mail address already exists! ");
                return Ok(new ApiResponse<bool> { Success = false, Message = "User with this email address already exists!", Data = false });
            }

            AppUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                FirstName = model.Firstname,
                LastName = model.Lastname
            };
            var result = await _userManager.CreateAsync(user, model.Password!);
            if (!result.Succeeded)
            {
                _logger.LogWarning("AUDIT: Register new user failed. " + result.Errors.ToList()[0]);
                return Ok(new ApiResponse<bool> { Success = false, Message = "User creation failed! Please check user details and  try again.", Data = true });
            }

            var nUser = await _userManager.FindByEmailAsync(model.Email!);
            var confirmationToken = Guid.NewGuid();
            nUser!.EmailVerifyToken = confirmationToken.ToString();
            await _userManager.UpdateAsync(nUser);
            var url = _configuration["Client:url"] + "/ConfirmEmail/" + nUser.Id + "/" + confirmationToken;
            var cmod = new MailConfirmModel
            {
                url = url,
                name = nUser.UserName!

            };
            EmailJob job = new EmailJob();
            job.CreatedOn = DateTime.Now;
            job.Finished = false;
            job.Receiver = nUser.Email!;
            job.Subject = "SecVault: Please confirm your email address";
            job.Template = "MailConfirm";
            job.objectModel = JsonSerializer.Serialize(cmod);
            _context.EmailJobs!.Add(job);
            await _context.SaveChangesAsync();

            nUser.RolesCombined = "User";
            await _userManager.AddToRoleAsync(nUser, "User");
            await _userManager.UpdateAsync(nUser);
            _logger.LogInformation("AUDIT: Register new user (" + nUser.UserName + ") successful");
            return Ok(new ApiResponse<Boolean> { Success = true, Message = "User created successfully! Please verify your email address before you try to <a href='/login'>login</a>.", Data = true });
        }

        /// <summary>
        /// second method to reset a password
        /// </summary>
        /// <param name="model"></param>
        /// <remarks>
        /// Sample request: 
        /// GET <![CDATA[api/Authentication/resetPw2]]>
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type bool</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpPost("resetPw2")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
        public async Task<IActionResult> ResetPw2(PasswordResetModel model)
        {
            ApiResponse<bool> res = new ApiResponse<bool>();
            var user = await _userManager.FindByIdAsync(model.UserId!);
            if (user != null)
            {
                if (user.ResetToken != model.Token)
                {
                    _logger.LogWarning("AUDIT: Password reset STEP2 for user" + user.UserName + " failed. Invalid token.");
                    res.Success = false;
                    res.Data = false;
                    res.Message = "Password reset failed. Invalid token!";
                    return Ok(res);
                }

                user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, model.Password!);
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogWarning("AUDIT: Password reset STEP2 for user" + user.UserName + " failed. " + result.Errors.ToString());
                    res.Success = false;
                    res.Data = false;
                    res.Message = "Password reset failed. Unable to upadte user object.";
                    return Ok(res);
                }

                user.LockoutEnabled = false;
                user.ResetToken = string.Empty;
                await _userManager.UpdateAsync(user);

                var url = _configuration["Client:url"] + "/Login";
                var cmod = new MailConfirmModel
                {
                    url = url,
                    name = user.UserName!
                };
                EmailJob job = new EmailJob();
                job.CreatedOn = DateTime.Now;
                job.Finished = false;
                job.Receiver = user.Email!;
                job.Subject = "GroupVault: Password reset completed..";
                job.Template = "ResetPw2";
                job.objectModel = JsonSerializer.Serialize(cmod);
                _context.EmailJobs!.Add(job);
                await _context.SaveChangesAsync();
                // await _mail.sendMailAsync(user.Email, "SecVault: Password reset completed..", "ResetPw2", cmod);
                _logger.LogWarning("AUDIT: Password reset Step2 for user" + user.UserName + " successful. Account unlocked, mail sended.");

                res.Success = true;
                res.Data = true;
                return Ok(res);
            }
            _logger.LogInformation("AUDIT: Reset Password Step2 failed. User with id " + model.UserId + " not found.");
            res.Success = false;
            res.Data = false;
            res.Message = "Reset Password Step2 failed. User with id " + model.UserId + " not found.";
            return Ok(res);
        }

        /// <summary>
        /// first methodto reset a password
        /// </summary>
        /// <param name="email"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     GET <![CDATA[api/Authentication/resetPw1?email=user@example.com]]>
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type bool</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpGet("resetPw1")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
        public async Task<IActionResult> ResetPw1(string email)
        {
            ApiResponse<bool> res = new ApiResponse<bool>();
            if (!String.IsNullOrEmpty(email))
            {
                var userExists = await _userManager.FindByEmailAsync(email);
                if (userExists != null)
                {
                    if (!String.IsNullOrEmpty(userExists.ResetToken))
                    {
                        _logger.LogWarning("AUDIT: Password reset attempt for user" + userExists.UserName + " failed. User has open request.");
                        res.Message = "Password reset not possible. There is an open password reset request already. Please contact your administrator!";
                        res.Success = false;
                        res.Data = false;
                        return Ok(res);
                    }
                    if (!String.IsNullOrEmpty(userExists.EmailVerifyToken))
                    {
                        _logger.LogWarning("AUDIT: Password reset attempt for user" + userExists.UserName + " failed.Email adress not confirmed.");
                        res.Message = "Password reset not possible. Email not verified. Please contact your administrator!";
                        res.Success = false;
                        res.Data = false;
                        return Ok(res);
                    }
                    if (userExists.LockoutEnabled == true)
                    {
                        _logger.LogWarning("AUDIT: Password reset attempt for user" + userExists.UserName + " failed. Account locked.");
                        res.Message = "Password reset not possible. Account is locked. Please contact your administrator!";
                        res.Success = false;
                        res.Data = false;
                        return Ok(res);
                    }
                    userExists.LockoutEnabled = true;
                    userExists.ResetToken = Guid.NewGuid().ToString();
                    await _userManager.UpdateAsync(userExists);
                    var url = _configuration["Client:url"] + "/ResetPw2/" + userExists.Id + "/" + userExists.ResetToken;
                    var cmod = new MailConfirmModel
                    {
                        url = url,
                        name = userExists.UserName!

                    };
                    EmailJob job = new EmailJob();
                    job.CreatedOn = DateTime.Now;
                    job.Finished = false;
                    job.Receiver = userExists.Email!;
                    job.Subject = "GroupVault: Complete your Password Reset..";
                    job.Template = "ResetPw1";
                    job.objectModel = JsonSerializer.Serialize(cmod);
                    _context.EmailJobs!.Add(job);
                    await _context.SaveChangesAsync();
                    //await _mail.sendMailAsync(userExists.Email, "SecVault: Complete your Password Reset..", "ResetPw1", cmod);
                    _logger.LogWarning("AUDIT: Password reset Step1 for user" + userExists.UserName + " successful. Account locked, mail sended.");
                    res.Data = true;
                    res.Success = true;
                    res.Message = "Password reset intitiated. Please take a look into your inbox!";
                    return Ok(res);
                }
                else
                {
                    _logger.LogWarning("AUDIT: Password reset attempt for user" + email + " failed. Email address not found.");
                    res.Success = false;
                    res.Message = "Email address not found!";
                    res.Data = false;
                    return Ok(res);
                }
            }
            res.Success = false;
            res.Data = false;
            return Ok(res);
        }

        /// <summary>
        /// method to verify a email confirmation
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     GET <![CDATA[api/Authentication/confirmEmail?userId=6554163463&token=dff65g47hf65f4gj6gf]]>
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type bool</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpGet("confirmEmail")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            ApiResponse<bool> res = new ApiResponse<bool>();
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = false;
                if (user.EmailVerifyToken == token && user.Id == userId)
                {
                    user.LockoutEnabled = false;
                    user.EmailVerifyToken = string.Empty;
                    user.EmailConfirmed = true;
                    await _userManager.UpdateAsync(user);
                    result = true;
                }

                if (result)
                {
                    _logger.LogInformation("AUDIT: " + user.UserName + " confirmed email adress successfully");
                    var cmod = new MailConfirmModel
                    {
                        url = _configuration["Client:url"] + "/Login",
                        name = user.UserName!

                    };
                    EmailJob job = new EmailJob();
                    job.CreatedOn = DateTime.Now;
                    job.Finished = false;
                    job.Receiver = user.Email!;
                    job.Subject = "GroupVault: Welcome to GroupVault!";
                    job.Template = "WelcomeRegister";
                    job.objectModel = JsonSerializer.Serialize(cmod);
                    _context.EmailJobs!.Add(job);
                    await _context.SaveChangesAsync();
                    //await _mail.sendMailAsync(user.Email, "SecVault: Welcome to SecVault!", "WelcomeRegister", cmod);
                    res.Success = true;
                    res.Data = true;
                    return Ok(res);
                }
                else
                {
                    _logger.LogInformation("AUDIT: " + user.UserName + " email confirmation failed. Invalid token.");
                    res.Success = false;
                    res.Data = false;
                    res.Message = "Email confirmation failed. Invalid token!";
                    return Ok(res);
                }
            }
            _logger.LogInformation("AUDIT: mail confirmation failed. User with id " + userId + " not found.");
            res.Success = false;
            res.Data = false;
            res.Message = "Email confirmation failed. User not found!";
            return Ok(res);
        }

        /// <summary>
        /// Retrieves information about the currently authenticated user.
        /// </summary>
        /// <remarks>This endpoint returns the authentication status and claims of the current user.  If
        /// the user is not authenticated, the response will be a 401 Unauthorized status.</remarks>
        /// <returns>An <see cref="IActionResult"/> containing either: <list type="bullet"> <item> <description>A 200 OK response
        /// with an object containing the user's authentication status and claims if the user is
        /// authenticated.</description> </item> <item> <description>A 401 Unauthorized response if the user is not
        /// authenticated.</description> </item> </list></returns>
        [HttpGet("me")]
        public IActionResult Me()
        {
            if (!User.Identity?.IsAuthenticated ?? false)
                return Unauthorized();

            var userInfo = new
            {
                IsAuthenticated = true,
                Claims = User.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList()
            };
            return Ok(userInfo);
        }



        /// <summary>
        /// method to refresh a jwt token
        /// </summary>
        /// <param name="tokenModel"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/refresh-token
        ///     {
        ///         "accessToken": "string",
        ///         "refreshToken": "string"
        ///     }
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type TokenResponse</response>
        /// <returns>a json object of type ApiResponse</returns>
        [HttpPost("refresh-token")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<TokenResponse>), StatusCodes.Status200OK)]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        {
            string? accessToken = tokenModel?.AccessToken;
            if (string.IsNullOrWhiteSpace(accessToken))
                accessToken = Request.Cookies["accessToken"];

            string? refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("No refresh token found.");
            if (string.IsNullOrEmpty(accessToken))
                return BadRequest("No access token provided.");


            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                _logger.LogWarning("AUDIT: Refresh token failed. No Principal from expired token.");
                return BadRequest("Invalid access token or refresh token");
            }

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            string username = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            var user = await _userManager.FindByNameAsync(username!);

            if (user == null)
            {
                _logger.LogWarning("AUDIT: Refresh token failed. No User Object from expired access token! ");
                return BadRequest("Refresh token failed. No User Object from expired access token!");
            }
            else if (user!.RefreshToken != refreshToken)
            {
                _logger.LogWarning("AUDIT: Refresh token failed. Refresh token did not match! ");
                return BadRequest("Refresh token failed. Refresh token did not match!");
            }
            else if (user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                _logger.LogWarning("AUDIT: Refresh token failed. Refresh token expired! ");
                return BadRequest("Refresh token failed. Refresh token expired!");
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserName!),
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Name, user.UserName!),
                    new Claim(ClaimTypes.Email, user.Email!),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                    new Claim(ClaimTypes.Sid, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            if (userRoles != null)
            {
                var rlsComb = "";
                if (userRoles.Count() > 0 && userRoles.Count() <= 1)
                {
                    rlsComb = userRoles[0].ToString();
                }
                else
                {
                    for (int i = 0; i < userRoles.Count; i++)
                    {
                        if (i + 1 != userRoles.Count) { rlsComb += userRoles[i] + ","; }
                        else { rlsComb += userRoles[i]; }
                    }
                }
                if (rlsComb.Length > 0)
                {
                    var rolesCombinedClaim = new Claim(JwtRegisteredClaimNames.Amr, rlsComb);
                    authClaims.Add(rolesCombinedClaim);
                }

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
            }

            var mfaClaim = new Claim("mfaEnabled", user.TwoFactorEnabled.ToString());
            authClaims.Add(mfaClaim);

            if(user.TwoFactorAuthToken!=null) {
                var mfaTokenClaim = new Claim("mfaAuthToken", user.TwoFactorAuthToken.ToString());
                authClaims.Add(mfaTokenClaim);
            }            

            var mfaEnfClaim = new Claim("mfaEnforced", user.IsMfaForce.ToString());
            authClaims.Add(mfaEnfClaim);

            var rolesClaim = new Claim("rlsComb", user.RolesCombined!);
            authClaims.Add(rolesClaim);

            var usernameClaim = new Claim("username", user.UserName!);
            authClaims.Add(usernameClaim);

            var firstnameClaim = new Claim("firstname", user.FirstName!);
            authClaims.Add(firstnameClaim);

            var lastnameClaim = new Claim("lastname", user.LastName!);
            authClaims.Add(lastnameClaim);

            var newAccessToken = CreateToken(authClaims);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);
            TokenResponse tks = new TokenResponse();
            ApiResponse<TokenResponse> res = new ApiResponse<TokenResponse>();
            tks.access_token = new JwtSecurityTokenHandler().WriteToken(newAccessToken);
            tks.refresh_token = newRefreshToken;
            res.Success = true;
            res.Data = tks;

            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddDays(1),
                Path = "/"
            });
            Response.Cookies.Append("accessToken", tks.access_token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddHours(1),
                Path = "/"
            });

            _logger.LogInformation("AUDIT: Refreshing token for user " + user.UserName + " successful!");
            return Ok(res);
        }

        /// <summary>
        /// validate a jwt token
        /// </summary>
        /// <returns></returns>
		[Authorize]
        private IActionResult ValidateToken()
        {
            return Ok();
        }

        /// <summary>
        /// revoke a jwt token for a user
        /// </summary>
        /// <param name="username"></param>
        /// <remarks>
        /// Sample request:
        /// 
        ///     POST api/Authentication/revoke
        ///     {
        ///         "username": "string"
        ///     }
        /// </remarks>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type string</response>
        /// <returns>a json object of type ApiResponse</returns>
		[Authorize(Roles = "Admin")]
        [HttpPost("revoke/{username}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<string>), StatusCodes.Status200OK)]
        public async Task<IActionResult> Revoke(string username)
        {
            ApiResponse<String> res = new ApiResponse<string>();
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                res.Success = false;
                res.Message = "Invalid user name";
                return Ok(res);
            }

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);

            res.Success = true;
            _logger.LogInformation("AUDIT: Revoking Refresh token for user " + user.UserName + " successful! ");
            res.Message = "User token revoked.";
            return Ok(res);
        }

        /// <summary>
        /// method to revoke all jwt tokens for all users
        /// </summary>
        /// <response code="200">returns a json object of type ApiResponse where Data field contains a object of type string</response>
        /// <returns>a json object of type ApiResponse</returns>
        [Authorize(Roles = "Admin")]
        [HttpPost("revoke-all")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ApiResponse<string>), StatusCodes.Status200OK)]
        public async Task<IActionResult> RevokeAll()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }
            _logger.LogInformation("AUDIT: Successfully deleted all Refresh tokens! ");
            return Ok(new ApiResponse<String> { Success = true });
        }

        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            string signingKey = Environment.GetEnvironmentVariable("G_SECRET") ?? _configuration["JWT:Secret"]!;
            string tokenVilidityInMInutes = Environment.GetEnvironmentVariable("G_TOKENVALIDITYINMINUTES") ?? _configuration["JWT:TokenValidityInMinutes"]!;
            string validIssuer = Environment.GetEnvironmentVariable("G_VALIDISSUER") ?? _configuration["JWT:ValidIssuer"]!;
            string validAudience = Environment.GetEnvironmentVariable("G_VALIDAUDIENCE") ?? _configuration["JWT:ValidAudience"]!;
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            _ = int.TryParse(tokenVilidityInMInutes, out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: validIssuer,
                audience: validAudience,
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        /// <summary>
        /// method to create arefresh token
        /// </summary>
        /// <returns></returns>
        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        /// <summary>
        /// extract a user principal from a expired token
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            string signingKey = Environment.GetEnvironmentVariable("G_SECRET") ?? _configuration["JWT:Secret"]!;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }

        #region "LDAP AUTHENTICATION"
        /// <summary>
        /// method to get groups for a user
        /// </summary>
        /// <param name="_ldapConnection">the active ldap connection</param>
        /// <param name="user">the username</param>
        /// <param name="LDAPBaseDn">the base dn of the ldap connection</param>
        /// <returns>a IEnumerable List oft group names</returns>
        private IEnumerable<string> GetGroupsForUserCore(LdapConnection _ldapConnection, string user, string LDAPBaseDn)
        {
            LdapSearchQueue searchQueue = _ldapConnection.Search(

                LDAPBaseDn,
                LdapConnection.ScopeSub,
                $"(sAMAccountName={user})",
                new string[] { "cn", "memberOf" },
                false,
                null as LdapSearchQueue);

            LdapMessage message;
            while ((message = searchQueue.GetResponse()) != null)
            {
                if (message is LdapSearchResult searchResult)
                {
                    LdapEntry entry = searchResult.Entry;
                    foreach (string value in HandleEntry(entry))
                        yield return value;
                }
                else
                    continue;
            }

            IEnumerable<string> HandleEntry(LdapEntry entry)
            {
                LdapAttribute attr = entry.GetAttribute("memberOf");

                if (attr == null) yield break;

                foreach (string value in attr.StringValueArray)
                {
                    string groupName = GetGroup(value);
                    yield return groupName;
                }
            }

            string GetGroup(string value)
            {
                Match match = Regex.Match(value, "^CN=([^,]*)");

                if (!match.Success) return null!;

                return match.Groups[1].Value;
            }
        }

        /// <summary>
        /// method to create a table of group memberships
        /// </summary>
        /// <param name="lc"></param>
        /// <param name="username"></param>
        /// <param name="LDAPBaseDn"></param>
        /// <returns></returns>
        private Stack<string> createGroupsTable(LdapConnection lc, string username, string LDAPBaseDn)
        {
            // check for group membership
            var groups = new Stack<string>();
            var uniqueGroups = new HashSet<string>();


            foreach (string group in this.GetGroupsForUserCore(lc, username, LDAPBaseDn))
            {
                groups.Push(group);
            }
            return groups;
        }

        /// <summary>
        /// method to authenticate agains an ldap server
        /// </summary>
        /// <param name="_usr">the username</param>
        /// <param name="userpw">the users password</param>
        /// <returns>bool</returns>
        private bool makeLDAPAuth(AppUser _usr, string userpw)
        {

            int ldapPort = LdapConnection.DefaultPort;
            int ldapVersion = LdapConnection.LdapV3;
            String ldapHost = _sett.Ldap.LdapDomainController!;
            String loginDN = _sett.Ldap.LdapDomainName + @"\" + _usr.UserName;
            String password1 = userpw;
            LdapConnection lc = new LdapConnection();

            // connect to the server
            lc.Connect(ldapHost, ldapPort);
            var sdn = lc.GetSchemaDn();

            // authenticate to the server
            lc.Bind(ldapVersion, loginDN, password1);
            string authDN = lc.AuthenticationDn.ToString();

            if (authDN.ToString().Contains(loginDN) == true)
            {

                Stack<string> gr = createGroupsTable(lc, _usr.UserName!, _sett.Ldap.LdapBaseDn!);
                bool erg = gr.Contains(_sett.Ldap.LdapGroup!);

                if (erg)
                {
                    lc.Disconnect();
                    return true;
                }
                else
                {
                    // ldap auth succes but user not in required group
                    lc.Disconnect();
                    return false;
                }
            }
            else
            {
                lc.Disconnect();
                return false;
            }
        }
        #endregion

    }
}
