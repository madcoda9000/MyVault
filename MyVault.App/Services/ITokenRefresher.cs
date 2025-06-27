namespace MyVault.App.Services
{
    public interface ITokenRefresher
    {
        Task<bool> RefreshTokenAsync();
    }

}
