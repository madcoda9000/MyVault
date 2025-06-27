namespace MyVault.App.Services
{
    public interface IBlazoredTokenStore
    {
        Task<string?> GetAccessTokenAsync();
        Task<string?> GetRefreshTokenAsync();
        Task SetTokensAsync(string accessToken, string refreshToken);
        Task RemoveTokensAsync();
    }
}
