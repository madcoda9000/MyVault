using System.ComponentModel.DataAnnotations;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// login  model
    /// </summary>
    public class LoginModel
    {
        /// <summary>
        /// username property
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "User Name is required")]
        public string? Username { get; set; }

        /// <summary>
        /// password property
        /// </summary>
        /// <value></value>
        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
