using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DOMAIN;

namespace XONT.Ventura.TaskGateway;
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }
    [AllowAnonymous]
    [HttpPost("generatetoken")]
    public IActionResult GenerateToken([FromBody] UserLogin model)
    {
        string message = string.Empty;
        string token = _authService.GenerateToken(model,ref message);

        return Ok(new { Token = token });
    }

}
