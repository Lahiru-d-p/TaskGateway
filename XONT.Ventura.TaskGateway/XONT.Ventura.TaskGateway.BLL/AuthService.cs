using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using XONT.Common.Data;
using XONT.Ventura.AppConsole;
using XONT.Ventura.TaskGateway.DAL;
using XONT.Ventura.TaskGateway.DOMAIN;

namespace XONT.Ventura.TaskGateway.BLL
{
    public class AuthService : IAuthService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly AuthDAL _authDal;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public AuthService(IOptions<JwtSettings> jwtSettings,AuthDAL authDAL, IHttpContextAccessor httpContextAccessor,IConfiguration configuration)
        {
            _jwtSettings = jwtSettings.Value;
            _authDal = authDAL;
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

        public bool ValidateApiKey(string key, ref string message)
        {
            bool valid = false;
            var expectedApiKey = _configuration["AppConsoleApiKey"];
            if (string.IsNullOrWhiteSpace(expectedApiKey))
            {
                System.Diagnostics.Trace.TraceError("Error: Api Key not configured in Task Gateway.");
                message = "V4 Task Gateway Server configuration error.";
            }
            else if (string.IsNullOrWhiteSpace(key) || !string.Equals(key, expectedApiKey, StringComparison.Ordinal))
            {
                System.Diagnostics.Trace.TraceError($"Unauthorized access attempt to GenerateToken. Invalid or missing API Key. Provided: '{key}'");
                message = "Invalid API Key.";
            }
            else
            {
                valid = true;
            }
            return valid;

        }
        public string GenerateToken(UserLogin model, ref string message)
        {
            var user = AuthenticateUser(model, ref message);
            if (!string.IsNullOrWhiteSpace(message) || user==null)
            {
                return string.Empty;
            }
            var unAuthorizedTasks = GetUnAuthorizedTasksForUser(model.UserName, ref message);

            if (!string.IsNullOrWhiteSpace(message))
            {
                return string.Empty;
            }

            var businessUnit = GetBusinessUnit(user, ref message);
            if (businessUnit == null || !string.IsNullOrWhiteSpace(message))
                return string.Empty;

            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                return string.Empty;
            }

            var sessionId = httpContext.Session.Id;
            SetSessionData(httpContext, user, businessUnit, unAuthorizedTasks);

            var token = BuildJwtToken(user, sessionId);
            return token;

        }

        #region Helper Methods

        private User AuthenticateUser(UserLogin model, ref string message)
        {
            string username = AESEncrytDecry.DecryptStringAES(model.UserName);
            string password = AESEncrytDecry.DecryptStringAES(model.Password);
            string encryptedPassword = new StroEncript().Encript(password.Trim());

            return _authDal.GetUserInfo(username, encryptedPassword, ref message);
        }

        private List<string> GetUnAuthorizedTasksForUser(string userName, ref string message)
        {
            var dt = _authDal.GetUnAuthorizedTasks(userName, ref message);
            if (dt == null || dt.Rows.Count == 0 || !string.IsNullOrWhiteSpace(message))
                return new List<string>();
            if (!dt.Columns.Contains("TaskCode"))
                return new List<string>();
            return dt.AsEnumerable()
                    .Where(row => !string.IsNullOrWhiteSpace(row["TaskCode"]?.ToString() ?? ""))
                    .Select(row => row["TaskCode"]?.ToString() ??"")
                    .ToList();
        }

        private BusinessUnit GetBusinessUnit(User user, ref string message)
        {
            return _authDal.GetBusinessUnit(user.BusinessUnit, user.DistributorCode, ref message);
        }

        private void SetSessionData(HttpContext context, User user, BusinessUnit businessUnit, List<string> unauthorizedTasks)
        {
            context.Session.SetObject("SessionID", context.Session.Id);
            context.Session.SetObject("Theme", user.Theme ?? "Blue");
            context.Session.SetObject("Main_Language", SetDefaultLanguage(ref user));
            context.Session.SetObject("Main_UserName", user.UserName.Trim());
            context.Session.SetObject("Main_BusinessUnit", user.BusinessUnit.Trim());
            context.Session.SetObject("Main_LoginUser", user);
            context.Session.SetObject("Main_BusinessUnitDetail", businessUnit);
            context.Session.SetObject("UnAuthorizedTasks", unauthorizedTasks);
        }

        private string BuildJwtToken(User user, string sessionId)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName.Trim()),
            new Claim("BusinessUnit", user.BusinessUnit.Trim()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            var token = new JwtSecurityToken(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private int SetDefaultLanguage(ref User user)
        {
            try
            {
                return user.Language?.Trim() switch
                {
                    "English" => (int)LanguageChange.Language.English,
                    "Sinhala" => (int)LanguageChange.Language.Sinhala,
                    "Tamil" => (int)LanguageChange.Language.Tamil,
                    _ => SetDefaultLanguageFallback(ref user)
                };
            }
            catch
            {
                return SetDefaultLanguageFallback(ref user);
            }
        }

        private int SetDefaultLanguageFallback(ref User user)
        {
            user.Language = "English";
            return (int)LanguageChange.Language.English;
        }

        #endregion
    }

}
