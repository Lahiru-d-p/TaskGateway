using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace XONT.Ventura.TaskGateway.Middlewares
{
    public class JwtWithSessionAuthenticationHandler : JwtBearerHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public JwtWithSessionAuthenticationHandler(
            IOptionsMonitor<JwtBearerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            IHttpContextAccessor httpContextAccessor)
            : base(options, logger, encoder)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var result = await base.HandleAuthenticateAsync();

            if (!result.Succeeded)
            {
                return result;
            }

            var context = _httpContextAccessor.HttpContext;

            if (context?.Session == null || !context.Session.Keys.Contains("Main_LoginUser"))
            {
                return AuthenticateResult.Fail("Session is missing or expired.");
            }

            return result;
        }
    }
}