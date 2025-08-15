
using Microsoft.AspNetCore.Http;
using XONT.Ventura.TaskGateway.DOMAIN;

namespace XONT.Ventura.TaskGateway.BLL
{
    public interface IAuthService
    {
        string GenerateToken(UserLogin modal, ref string message);
        bool ValidateApiKey(string key, ref string message);

    }
}
