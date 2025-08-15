using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net;
using System.Threading.Tasks;

namespace XONT.Ventura.TaskGateway.Middlewares
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionValidationMiddleware> _logger;

        public SessionValidationMiddleware(RequestDelegate next, ILogger<SessionValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            var controller = httpContext.Request.RouteValues["controller"]?.ToString();
            if (controller != "Auth" && (httpContext.Session == null || !httpContext.Session.Keys.Contains("Main_LoginUser")))
            {
                _logger.LogError("User Session not Available");
                httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await httpContext.Response.WriteAsync("Unauthorized: Session or user data missing.");
                return;

            }
            else
            {
                await _next(httpContext);
            }

        }
    }
}