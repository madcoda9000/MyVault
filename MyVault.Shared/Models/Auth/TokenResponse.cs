namespace MyVault.Shared.Models.Auth
{
	/// <summary>
	/// model for token response
	/// </summary>
	public class TokenResponse
	{
		/// <summary>
		/// property access_token
		/// </summary>
		/// <value></value>
		public string? access_token { get; set; }
		/// <summary>
		/// property refresh_token
		/// </summary>
		/// <value></value>
		public string? refresh_token { get; set; }
	}
}
