using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Shared.Models.FormModels
{
    /// <summary>
    /// paged post model
    /// </summary>
    public class PagedPostModel
    {
        /// <summary>
        /// page property
        /// </summary>
        /// <value></value>
        public int page {get; set;}
        /// <summary>
        /// page size property
        /// </summary>
        /// <value></value>
        public int pageSize {get; set;}
        /// <summary>
        /// serach value property
        /// </summary>
        /// <value></value>
        public string searchValue {get; set;} = String.Empty;
    }
}