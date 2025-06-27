using System.ComponentModel.DataAnnotations;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// register mdoel
    /// </summary>
    public class RegisterModel
    {
        /// <summary>
        /// username property
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "User Name is required")]
        public string? Username { get; set; }

        /// <summary>
        /// email proeprty
        /// </summary>
        /// <value></value>
        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }

        /// <summary>
        /// password proeprty
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
        /// <summary>
        /// firstname proeprty
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "Firstname is required")]
        public string? Firstname { get; set; }
        /// <summary>
        /// lastname proeprty
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "Lastname is required")]
        public string? Lastname { get; set; }
    }
}
