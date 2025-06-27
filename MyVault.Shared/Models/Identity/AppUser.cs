using Microsoft.AspNetCore.Identity;
using System.Text.Json.Serialization;

namespace MyVault.Shared.Models.Identity
{
    /// <summary>
    /// class to define a user object
    /// </summary>
    public class AppUser : IdentityUser
    {
        /// <summary>
        /// birthday property
        /// </summary>
        /// <value>DateTime</value>
        public DateTime BirthDay { get; set; }
        /// <summary>
        /// birthday CreatedOn
        /// </summary>
        /// <value>DateTime</value>
        public DateTime CreatedOn { get; set; }
        /// <summary>
        /// firstname property
        /// </summary>
        /// <value>string</value>
        public String? FirstName { get; set; } = string.Empty;
        /// <summary>
        /// lastname property
        /// </summary>
        /// <value>string</value>
        public String? LastName { get; set; } = string.Empty;
        /// <summary>
        /// 2fa force property
        /// </summary>
        /// <value>bool</value>
        public bool IsMfaForce { get; set; }
        /// <summary>
        /// ldap login property
        /// </summary>
        /// <value>bool</value>
        public bool IsLdapLogin { get; set; }
        /// <summary>
        /// department property
        /// </summary>
        /// <value>Department</value>
        public string? Department { get; set; } = string.Empty;
        /// <summary>
        /// profile picture proerty
        /// </summary>
        /// <value>string</value>
        public string? ProfilePicture { get; set; }
        /// <summary>
        /// account enbaled property
        /// </summary>
        /// <value>bool</value>
        public bool IsEnabled { get; set; }
        /// <summary>
        /// roles combined property
        /// </summary>
        /// <value></value>
        public string? RolesCombined { get; set; } = string.Empty;
        /// <summary>
        /// refresh token
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public string? RefreshToken { get; set; }
        /// <summary>
        /// TwoFactorSecret
        /// </summary>
        /// <value></value>
        public string? TwoFactorSecret { get; set; }
        /// <summary>
        /// TwoFactorAuthToken
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public string? TwoFactorAuthToken { get; set; }
        /// <summary>
        /// refresh token expiary
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public DateTime RefreshTokenExpiryTime { get; set; }
        /// <summary>
        /// password hash property
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public override string? PasswordHash {get;set;}
        /// <summary>
        /// lockout end time
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public override DateTimeOffset? LockoutEnd { get => base.LockoutEnd; set => base.LockoutEnd = value; }
        /// <summary>
        ///  concurrency timestamp
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public override string? ConcurrencyStamp { get => base.ConcurrencyStamp; set => base.ConcurrencyStamp = value; }
        /// <summary>
        /// access fialed counter
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public override int AccessFailedCount { get => base.AccessFailedCount; set => base.AccessFailedCount = value; }
        /// <summary>
        /// phone number confirmed
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public override bool PhoneNumberConfirmed { get => base.PhoneNumberConfirmed; set => base.PhoneNumberConfirmed = value; }
        /// <summary>
        /// security stamp
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public override string? SecurityStamp { get => base.SecurityStamp; set => base.SecurityStamp = value; }
        /// <summary>
        /// reset token property
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public string ResetToken {get;set;} = string.Empty;
        /// <summary>
        /// email verification token
        /// </summary>
        /// <value></value>
        [JsonIgnore]
        public string EmailVerifyToken {get;set;} = string.Empty;

    }
}