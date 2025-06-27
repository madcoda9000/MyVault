using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Server.Helper
{
    /// <summary>
    /// PagedData class
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class PagedData<T> where T:class
    {
        /// <summary>
        /// Data property
        /// </summary>
        /// <value></value>
        public IEnumerable<T>? PagedList { get; set; }
        /// <summary>
        /// total pages property
        /// </summary>
        /// <value></value>
        public int TotalPages { get; set; }
        /// <summary>
        /// current page property
        /// </summary>
        /// <value></value>
        public int CurrentPage { get; set; }
        /// <summary>
        /// the total item count
        /// </summary>
        /// <value></value>
        public int TotalItemsCount {get; set;}
    }
}