using MyVault.App.Services;

public class AuthRetryHandler : DelegatingHandler
{
    private readonly IBlazoredTokenStore _tokenStore;
    private readonly ITokenRefresher _tokenRefresher;

    public AuthRetryHandler(IBlazoredTokenStore tokenStore, ITokenRefresher tokenRefresher)
    {
        _tokenStore = tokenStore;
        _tokenRefresher = tokenRefresher;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Füge AccessToken im Header ein
        var accessToken = await _tokenStore.GetAccessTokenAsync();
        if (!string.IsNullOrEmpty(accessToken))
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // Einmal refresh versuchen (ohne AuthService)
            if (await _tokenRefresher.RefreshTokenAsync())
            {
                accessToken = await _tokenStore.GetAccessTokenAsync();
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                response.Dispose();
                return await base.SendAsync(request, cancellationToken);
            }
        }
        return response;
    }
}
