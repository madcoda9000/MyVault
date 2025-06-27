using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.DataModels
{
    /// <summary>
    /// class for email jobs definition
    /// </summary>
    [Table("EmailJobs")]
    public class EmailJob
    {
        /// <summary>
        /// the id column
        /// </summary>
        /// <value></value>
        [Key]
        public Guid Id { get; set; }
        /// <summary>
        /// created on column
        /// </summary>
        /// <value></value>
        public DateTime CreatedOn { get; set; } = DateTime.UtcNow;
        /// <summary>
        /// FinishedOn column
        /// </summary>
        /// <value></value>
        public DateTime? FinishedOn { get; set; }
        /// <summary>
        /// sender column
        /// </summary>
        public String Sender { get; set; } = string.Empty;
        /// <summary>
        /// receiver column
        /// </summary>
        public String Receiver { get; set; } = string.Empty;
        /// <summary>
        /// Subject column
        /// </summary>
        public String Subject { get; set; } = string.Empty;
        /// <summary>
        /// mail template column
        /// </summary>
        public String Template { get; set; } = string.Empty;
        /// <summary>
        /// object model column
        /// </summary>
        /// <value></value>
        public String objectModel {get;set;} = string.Empty;
        /// <summary>
        /// finished column
        /// </summary>
        /// <value></value>
        public Boolean Finished { get; set; } = false;
    }
}