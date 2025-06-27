using Blazored.SessionStorage;

namespace MyVault.App.Services
{
    public class BlazoredTokenStore : IBlazoredTokenStore
    {
        private readonly ISessionStorageService _sessionStorage;
        public BlazoredTokenStore(ISessionStorageService sessionStorage) => _sessionStorage = sessionStorage;

        public async Task<string?> GetAccessTokenAsync() => await _sessionStorage.GetItemAsync<string>("accessToken");
        public async Task<string?> GetRefreshTokenAsync() => await _sessionStorage.GetItemAsync<string>("refreshToken");

        public async Task SetTokensAsync(string accessToken, string refreshToken)
        {
            await _sessionStorage.SetItemAsync("accessToken", accessToken);
            await _sessionStorage.SetItemAsync("refreshToken", refreshToken);
        }
        public async Task RemoveTokensAsync()
        {
            await _sessionStorage.RemoveItemAsync("accessToken");
            await _sessionStorage.RemoveItemAsync("refreshToken");
        }
    }
}
