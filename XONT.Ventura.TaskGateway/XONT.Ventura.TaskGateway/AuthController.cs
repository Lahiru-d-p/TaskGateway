using Microsoft.AspNetCore.Mvc;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DOMAIN;

namespace XONT.Ventura.TaskGateway;
[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("generatetoken")]
    public IActionResult GenerateToken([FromBody] UserLogin model)
    {
        string message = string.Empty;
        string token = _authService.GenerateToken(model,ref message);

        return Ok(new { Token = token });
    }

}
