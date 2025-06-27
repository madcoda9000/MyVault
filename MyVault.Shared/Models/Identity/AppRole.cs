using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace MyVault.Shared.Models.Identity
{
    /// <summary>
    /// class to define a role object
    /// </summary>
    public class AppRole : IdentityRole
    {
        /// <summary>
        /// property created on
        /// </summary>
        /// <value>DateTime</value>
        public DateTime CreatedOn { get; set; }
    }
}