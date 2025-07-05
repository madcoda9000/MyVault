using MyVault.Shared.Models.Auth;
using System.Net.Http.Json;

namespace MyVault.App.Services
{
    public class TokenRefresher : ITokenRefresher
    {
        private readonly HttpClient _http;
        private readonly IBlazoredTokenStore _tokenStore;

        public TokenRefresher(IHttpClientFactory factory, IBlazoredTokenStore tokenStore)
        {
            _http = factory.CreateClient("AuthClient"); // Achtung: ein eigener Client, ohne AuthRetryHandler!
            _tokenStore = tokenStore;
        }

        public async Task<bool> RefreshTokenAsync()
        {
            var refreshToken = await _tokenStore.GetRefreshTokenAsync();
            var accessToken = await _tokenStore.GetAccessTokenAsync();
            if (refreshToken == null || accessToken == null) return false;

            var response = await _http.PostAsJsonAsync("/api/authenticate/refresh-token", new { AccessToken = accessToken, RefreshToken = refreshToken });
            if (!response.IsSuccessStatusCode)
                return false;

            var apiResult = await response.Content.ReadFromJsonAsync<ApiResponse<TokenResponse>>();
            if (apiResult is { Success: true, Data: var data })
            {
                if (data!= null && !string.IsNullOrEmpty(data.access_token) && !string.IsNullOrEmpty(data.refresh_token)) {
                    await _tokenStore.SetTokensAsync(data.access_token, data.refresh_token);
                    return true;
                } else {
                    return false;
                }
                
            }
            return false;
        }
    }

}
