using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
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
        UserLoginResponse response = new UserLoginResponse();
        try
        {
            string message = string.Empty;
            string token = _authService.GenerateToken(model, ref message);
            
            if(string.IsNullOrWhiteSpace(token) || !string.IsNullOrWhiteSpace(message))
            {
                response.Message = message ?? "Token Generation Failed";
                return Unauthorized(response);
            }
            else
            {
                response.Token = token;
                response.Message = "Token generated successfully.";
                return Ok(response);
            }
        }
        catch (Exception ex)
        {
            response.Message = $"An error occurred while generating the token : {ex.Message}";
            return StatusCode(StatusCodes.Status500InternalServerError, response);
        }
    }

    [Authorize]
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        try
        {
            if (HttpContext == null)
            {
                return BadRequest(new  { Message= "HTTP context is unavailable." });
            }

            HttpContext.Session.Clear();

            return Ok(new { Message = "Logout successful. Please discard your token." });
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { Message = $"Logout failed: {ex.Message}" });
        }
    }
}
