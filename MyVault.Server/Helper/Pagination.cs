using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Server.Helper
{
    /// <summary>
    /// Pagination class
    /// </summary>
    public static class Pagination
    {
        /// <summary>
        /// Paged Result funtion
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public static PagedData<T> PagedResult<T>(this IEnumerable<T> list, int PageNumber, int PageSize) where T : class
        {
            var result = new PagedData<T>();
            result.PagedList = list.Skip(PageSize * (PageNumber - 1)).Take(PageSize).ToList();
            result.TotalPages = Convert.ToInt32(Math.Ceiling((double)list.Count() / PageSize));
            result.CurrentPage = PageNumber;
            result.TotalItemsCount = list.Count();
            return result;
        }
    }
}