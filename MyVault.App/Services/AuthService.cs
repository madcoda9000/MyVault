using MyVault.Shared.Models.Auth;
using System.Net.Http.Json;

namespace MyVault.App.Services
{
    public class AuthService
    {
        private readonly HttpClient _http;
        private readonly IBlazoredTokenStore _tokenStore;

        public AuthService(IHttpClientFactory httpClientFactory, IBlazoredTokenStore tokenStore)
        {
            _http = httpClientFactory.CreateClient("ApiClient");
            _tokenStore = tokenStore;
        }

        /// <summary>
        /// Login und gibt das vollständige ApiResponse (mit Message, Success etc.) zurück.
        /// </summary>
        public async Task<ApiResponse<TokenResponse>?> LoginAsync(string username, string password)
        {
            var response = await _http.PostAsJsonAsync("/api/authenticate/login", new { Username = username, Password = password });

            ApiResponse<TokenResponse>? apiResult = null;
            try
            {
                apiResult = await response.Content.ReadFromJsonAsync<ApiResponse<TokenResponse>>();
            }
            catch { }

            // Wenn Login erfolgreich: Tokens speichern
            if (apiResult?.Success == true && apiResult.Data is { } data)
            {
                if (data.access_token == null || data.refresh_token == null)
                {
                    return new ApiResponse<TokenResponse> { Success = false, Message = "Login failed. Please check your credentials." };
                    
                }
                await _tokenStore.SetTokensAsync(data.access_token, data.refresh_token);
            }

            return apiResult;
        }

        /// <summary>
        /// Token-Refresh, gibt ApiResponse zurück (mit neuem Token oder Fehler).
        /// </summary>
        public async Task<ApiResponse<TokenResponse>?> RefreshTokenAsync()
        {
            var refreshToken = await _tokenStore.GetRefreshTokenAsync();
            var accessToken = await _tokenStore.GetAccessTokenAsync();
            if (refreshToken == null || accessToken == null)
                return new ApiResponse<TokenResponse> { Success = false, Message = "No token available." };

            var tokenModel = new TokenModel { AccessToken = accessToken, RefreshToken = refreshToken };
            var response = await _http.PostAsJsonAsync("/api/authenticate/refresh-token", tokenModel);

            ApiResponse<TokenResponse>? apiResult = null;
            try
            {
                apiResult = await response.Content.ReadFromJsonAsync<ApiResponse<TokenResponse>>();
            }
            catch { }

            if (apiResult?.Success == true && apiResult.Data is { } data)
            {
                if(data.access_token == null || data.refresh_token == null)
                {
                    return new ApiResponse<TokenResponse> { Success = false, Message = "Token refresh failed." };
                }
                await _tokenStore.SetTokensAsync(data.access_token, data.refresh_token);
            }

            return apiResult;
        }

        /// <summary>
        /// Logout: löscht Tokens lokal und ruft den Server ab.
        /// </summary>
        public async Task<ApiResponse<bool>?> LogoutAsync()
        {
            await _tokenStore.RemoveTokensAsync();
            var response = await _http.PostAsync("/api/authenticate/logout", null);

            ApiResponse<bool>? apiResult = null;
            try
            {
                apiResult = await response.Content.ReadFromJsonAsync<ApiResponse<bool>>();
            }
            catch { }

            return apiResult;
        }
    }

}
