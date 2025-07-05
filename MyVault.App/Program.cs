using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using MyVault.App;
using Blazored.SessionStorage;
using Microsoft.AspNetCore.Components.Authorization;
using MyVault.App.Services;
using MyVault.App.Utils;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddBlazoredSessionStorage();

builder.Services.AddScoped<IBlazoredTokenStore, BlazoredTokenStore>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ITokenRefresher, TokenRefresher>();
builder.Services.AddTransient<AuthRetryHandler>();

// API Client mit Handler f�r App Requests
builder.Services.AddHttpClient("ApiClient", client =>
{
    client.BaseAddress = new Uri("http://localhost:5206");
}).AddHttpMessageHandler<AuthRetryHandler>();

// AuthClient f�r TokenRefresher, ohne Handler!
builder.Services.AddHttpClient("AuthClient", client =>
{
    client.BaseAddress = new Uri("http://localhost:5206");
});

builder.Services.AddScoped<AuthenticationStateProvider, JwtAuthenticationStateProvider>();
builder.Services.AddAuthorizationCore();
builder.Services.AddFluentUIComponents();

await builder.Build().RunAsync();
