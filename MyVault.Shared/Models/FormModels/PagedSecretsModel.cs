using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// paged secrets model
    /// </summary>
    public class PagedSecretsModel
    {
        /// <summary>
        /// page number property
        /// </summary>
        /// <value></value>
        public int pageNumber {get; set;} = 1;
        /// <summary>
        /// page size property
        /// </summary>
        /// <value></value>
        public int pageSize {get; set;} = 10;
        /// <summary>
        /// serach value property
        /// </summary>
        /// <value></value>
        public string searchValue {get; set;} = String.Empty;
        /// <summary>
        /// role name property
        /// </summary>
        /// <value></value>
        public string roleName {get; set;} = String.Empty;
    }
}