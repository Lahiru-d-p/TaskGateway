using Microsoft.AspNetCore.Http;
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

        public AuthService(IOptions<JwtSettings> jwtSettings,AuthDAL authDAL, IHttpContextAccessor httpContextAccessor)
        {
            _jwtSettings = jwtSettings.Value;
            _authDal = authDAL;
            _httpContextAccessor = httpContextAccessor;
        }

        public string GenerateToken(UserLogin modal, ref string message)
        {

            string plainUN = AESEncrytDecry.DecryptStringAES(modal.UserName);
            string plainPW = AESEncrytDecry.DecryptStringAES(modal.Password);

            var stroEncript = new StroEncript();

            string encriptPsass = stroEncript.Encript(plainPW.Trim());
            User user = _authDal.GetUserInfo(plainUN,modal.Password, ref message);

            if (!string.IsNullOrWhiteSpace(message) || user==null)
            {
                return string.Empty;
            }
            var unAuthorizedTasks = GetUnAuthorizedTasksForUser(modal.UserName, ref message);

            if (!string.IsNullOrWhiteSpace(message))
            {
                return string.Empty;
            }

            BusinessUnit businessUnit = _authDal.GetBusinessUnit(user.BusinessUnit,user.DistributorCode, ref message);

            if (!string.IsNullOrWhiteSpace(message) || businessUnit == null )
            {
                return string.Empty;
            }
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                message = "HTTP context is unavailable.";
                return string.Empty;
            }

            var sessionIdCore = httpContext.Session.Id;
            httpContext.Session.SetString("SessionID",modal.SessionID);
            httpContext.Session.SetString("SessionIDCore", sessionIdCore);
            httpContext.Session.SetString("Theme",user.Theme);
            httpContext.Session.SetInt32("Main_Language", SetDefaultLanguage(ref user));
            httpContext.Session.SetString("Main_UserName",user.UserName);
            httpContext.Session.SetString("Main_BusinessUnit", user.BusinessUnit);
            httpContext.Session.SetObject<User>("Main_LoginUser", user);
            httpContext.Session.SetObject<BusinessUnit>("Main_BusinessUnitDetail", businessUnit);

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,modal.UserName),
                new Claim("businessUnit", user.BusinessUnit),
                new Claim("sessionID", modal.SessionID??""),
                new Claim("sessionIDCore", sessionIdCore??""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(_jwtSettings.Issuer,
              _jwtSettings.Audience,
              claims,
              expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);

        }
        private List<string> GetUnAuthorizedTasksForUser(string userName, ref string message)
        {
            var dt = _authDal.GetUnAuthorizedTasks(userName, ref message);
            var taskList = new List<string>();
            if (dt == null || dt.Rows.Count == 0 || !string.IsNullOrWhiteSpace(message))
            {
                return taskList;
            }

            foreach (DataRow dtRow in dt.Rows)
            {
                string taskCode = dtRow["TaskCode"]?.ToString() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(taskCode))
                {
                    taskList.Add(taskCode);
                }
            }

            return taskList;
        }

        private int SetDefaultLanguage(ref User user)
        {
            try
            {
                switch (user.Language.ToString().Trim())
                {
                    case ("English"):
                        return (int)LanguageChange.Language.English;
                    case ("Sinhala"):
                        return (int)LanguageChange.Language.Sinhala;
                    case ("Tamil"):
                        return (int)LanguageChange.Language.Tamil;
                    default:
                        user.Language = "English";
                        return (int)LanguageChange.Language.English;

                }
            }
            catch (Exception e)
            {
                user.Language = "English";
                return (int)LanguageChange.Language.English;
            }

        }
    }

}
