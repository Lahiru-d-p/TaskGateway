using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DOMAIN;

namespace XONT.Ventura.TaskGateway.Controllers;
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
            var providedApiKey = Request.Headers["X-API-Key"].FirstOrDefault() ?? ""; 
            var keyValid = _authService.ValidateApiKey(providedApiKey, ref message);
            if (!keyValid)
            {
                response.Message = message ?? "Invalid API Key.";
                return Unauthorized(response);
            }

            string token = _authService.GenerateToken(model, ref message);
            
            if(string.IsNullOrWhiteSpace(token) || !string.IsNullOrWhiteSpace(message))
            {
                response.Message = message ?? "Authorization Failed";
                return Unauthorized(response);
            }
            else
            {
                response.Token = token;
                response.Message = "Authorized successfully.";
                return Ok(response);
            }
        }
        catch (Exception ex)
        {
            response.Message = $"An error occurred while Authorization : {ex.Message}";
            return StatusCode(StatusCodes.Status500InternalServerError, response);
        }
    }

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
