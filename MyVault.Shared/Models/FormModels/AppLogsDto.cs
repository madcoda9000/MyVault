using Microsoft.Extensions.Logging;

namespace MyVault.Shared.Models.FormModels
{
    public class AppLogsDto
    {
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public LogLevel LogLevel { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string Exception { get; set; } = string.Empty;
    }
}
