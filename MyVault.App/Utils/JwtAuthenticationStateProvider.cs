using Microsoft.AspNetCore.Components.Authorization;
using MyVault.App.Services;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MyVault.App.Utils
{
    public class JwtAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly IBlazoredTokenStore _tokenStore;

        public JwtAuthenticationStateProvider(IBlazoredTokenStore tokenStore)
        {
            _tokenStore = tokenStore;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var accessToken = await _tokenStore.GetAccessTokenAsync();
            if (string.IsNullOrWhiteSpace(accessToken))
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

            // Token validieren und Claims extrahieren
            var identity = new ClaimsIdentity(ParseClaimsFromJwt(accessToken), "jwt");
            var user = new ClaimsPrincipal(identity);
            return new AuthenticationState(user);
        }

        public void NotifyUserAuthentication(string token)
        {
            var identity = new ClaimsIdentity(ParseClaimsFromJwt(token), "jwt");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }

        public void NotifyUserLogout()
        {
            var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymous)));
        }

        // JWT Claims "rauspopeln" (ohne Libs)
        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var claims = new List<Claim>();
            var payload = jwt.Split('.')[1];
            var jsonBytes = ParseBase64WithoutPadding(payload);
            var keyValuePairs = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

            if (keyValuePairs != null)
            {
                foreach (var kvp in keyValuePairs)
                {
                    if (kvp.Value is System.Text.Json.JsonElement el && el.ValueKind == System.Text.Json.JsonValueKind.Array)
                    {
                        foreach (var item in el.EnumerateArray())
                            claims.Add(new Claim(kvp.Key, item.ToString()!));
                    }
                    else
                    {
                        claims.Add(new Claim(kvp.Key, kvp.Value?.ToString()!));
                    }
                }
            }
            return claims;
        }

        private byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }

}
