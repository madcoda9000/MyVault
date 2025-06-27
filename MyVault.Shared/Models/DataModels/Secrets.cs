using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace MyVault.Shared.Models.DataModels
{
    /// <summary>
    /// model class for Secrets object
    /// </summary>
    [Index(nameof(S_Name),nameof(S_UserRoles),nameof(S_Username))]
    public class Secrets
    {
        /// <summary>
        /// id property
        /// </summary>
        /// <value></value>
        [Key]
        public int S_Id { get; set; }
        /// <summary>
        /// created property
        /// </summary>
        /// <value></value>
        public DateTime S_CreatedOn { get; set; } = DateTime.UtcNow;
        /// <summary>
        /// modified property
        /// </summary>
        /// <value></value>
        public DateTime S_ModifiedOn { get; set; } = DateTime.UtcNow;
        /// <summary>
        /// name property
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "This field is required")]
        public string? S_Name { get; set; }
        /// <summary>
        /// hostname property
        /// </summary>
        /// <value></value>
        public string S_HostName { get; set; } = String.Empty;
        /// <summary>
        /// url property
        /// </summary>
        /// <value></value>
        public string S_Url { get; set; } = String.Empty;
        /// <summary>
        /// url image property
        /// </summary>
        /// <value></value>
        public string S_Url_Image { get; set; } = String.Empty;
        /// <summary>
        /// username property
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "This field is required")]
        public string S_Username { get; set; } = String.Empty;
        /// <summary>
        /// password property
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "This field is required")]
        public string S_Password { get; set; } = String.Empty;
        /// <summary>
        /// description property
        /// </summary>
        /// <value></value>
        public string S_Description { get; set; } = String.Empty;
        /// <summary>
        /// attachment file name
        /// </summary>
        /// <value></value>
        public string S_AttachmentFileName { get; set; } = String.Empty;
        /// <summary>
        /// attachment mime type
        /// </summary>
        /// <value></value>
        public string S_AttachmentMimetype { get; set; } = String.Empty;
        /// <summary>
        /// attachment property
        /// </summary>
        /// <value></value>
        public byte[]? S_Attachment { get; set; }
        /// <summary>
        /// created by property
        /// </summary>
        /// <value></value>
        public string S_createdBy { get; set; } = String.Empty;
        /// <summary>
        /// user roles property
        /// </summary>
        /// <value></value>
        public string S_UserRoles { get; set; } = String.Empty;
        /// <summary>
        /// private property
        /// </summary>
        /// <value></value>
        public bool S_isPrivate { get; set; }
    }
}