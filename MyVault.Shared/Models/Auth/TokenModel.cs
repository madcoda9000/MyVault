namespace MyVault.Shared.Models.Auth
{
    /// <summary>
    /// auth token model 
    /// </summary>
    public class TokenModel
    {
        /// <summary>
        /// access token property
        /// </summary>
        /// <value></value>
        public string? AccessToken { get; set; }
        /// <summary>
        /// refresh token property
        /// </summary>
        /// <value></value>
        public string? RefreshToken { get; set; }
    }
}
