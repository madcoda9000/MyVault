using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyVault.Server.Middleware
{
    /// <summary>
    /// request logger class
    /// </summary>
    public class RequestLogger
    {
        /// <summary>
        /// delegate property
        /// </summary>
        private readonly RequestDelegate _next;
        /// <summary>
        /// logger rproperty
        /// </summary>
        private readonly ILogger<RequestLogger> _logger;

        /// <summary>
        /// class constructor
        /// </summary>
        /// <param name="next"></param>
        /// <param name="logger"></param>
        public RequestLogger(RequestDelegate next, ILogger<RequestLogger> logger)
        {
            _next = next;
            _logger = logger;
        }

        /// <summary>
        /// invoke method
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task Invoke(HttpContext context)
        {
            var request = context.Request;
            var response = context.Response;

            // Log the request
            //_logger.LogInformation("API: Request: {Method} {Path}", request.Method, request.Path);
            await logRequest(context);

            // log the response
            var originalResponseBody = context.Response.Body;

            using (var responseBody = new MemoryStream())
            {
                context.Response.Body = responseBody;
                await _next.Invoke(context);
                
                await LogResponse(context, responseBody, originalResponseBody);
            }

        }

        /// <summary>
        /// log response method
        /// </summary>
        /// <param name="context"></param>
        /// <param name="responseBody"></param>
        /// <param name="originalResponseBody"></param>
        /// <returns></returns>
        private async Task LogResponse(HttpContext context, MemoryStream responseBody, Stream originalResponseBody)
        {
            var responseContent = new StringBuilder();

            responseContent.AppendLine("API: Response " + context.TraceIdentifier + ": STATUS " + context.Response.StatusCode + ": PATH " + context.Response.HttpContext.Request.Path);
            responseContent.AppendLine("=== Response Info ===");
             
            responseContent.AppendLine("-- headers");
            foreach (var (headerKey, headerValue) in context.Response.Headers)
            {
                responseContent.AppendLine($"header = {headerKey}    value = {headerValue}");
            }

            responseContent.AppendLine("-- body");
            responseBody.Position = 0;
            var content = await new StreamReader(responseBody).ReadToEndAsync();
            responseContent.AppendLine($"body = {content}");
            responseBody.Position = 0;
            await responseBody.CopyToAsync(originalResponseBody);
            context.Response.Body = originalResponseBody;

            _logger.LogInformation(responseContent.ToString());
        }

        /// <summary>
        /// log request method
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task logRequest(HttpContext context) {
            var requestContent = new StringBuilder();
            
            requestContent.AppendLine("API: Request " + context.TraceIdentifier + ": " +  context.Request.Method + " " + context.Request.Path);
            requestContent.AppendLine("=== Request Info ===");
            requestContent.AppendLine($"method = {context.Request.Method.ToUpper()}");
            requestContent.AppendLine($"path = {context.Request.Path}");

            requestContent.AppendLine("-- headers");
            foreach (var (headerKey, headerValue) in context.Request.Headers)
            {
                requestContent.AppendLine($"header = {headerKey}    value = {headerValue}");
            }

            requestContent.AppendLine("-- body");
            context.Request.EnableBuffering();
            var requestReader = new StreamReader(context.Request.Body);
            var content = await requestReader.ReadToEndAsync();
            requestContent.AppendLine($"body = {content}");

            _logger.LogInformation(requestContent.ToString());
            context.Request.Body.Position = 0;
        } 
    }    

    /// <summary>
    /// logger extension class
    /// </summary>
    public static class RequestLoggerExtensions
    {
        /// <summary>
        /// attach method to application builder
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseRequestResponseLogging(this IApplicationBuilder app)
        {
            return app.UseMiddleware<RequestLogger>();
        }
    }
}