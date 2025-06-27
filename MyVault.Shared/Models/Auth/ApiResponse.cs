namespace MyVault.Shared.Models.Auth
{
    /// <summary>
    /// model class ApiRexponse
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ApiResponse<T>
    {
        /// <summary>
        /// property success
        /// </summary>
        /// <value></value>
        public Boolean Success { get; set; } = false;
        /// <summary>
        /// property data
        /// </summary>
        /// <value></value>
		public T? Data { get; set; }
        /// <summary>
        /// property Message
        /// </summary>
        /// <value></value>
        public string? Message { get; set; }
    }
}
