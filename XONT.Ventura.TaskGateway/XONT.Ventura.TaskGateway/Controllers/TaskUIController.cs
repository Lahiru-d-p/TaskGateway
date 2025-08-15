using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;

namespace XONT.Ventura.TaskGateway.Controllers
{
    [Authorize(Policy = "TaskAccess")]
    [Route("api/[controller]")]
    public class TaskUIController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;

        public TaskUIController(IWebHostEnvironment env)
        {
            _env = env;
        }

        [HttpGet("{taskid}/{**path}")]
        public IActionResult Get(string taskid, string path = "index.html")
        {
            try
            {
                if (string.IsNullOrEmpty(path) || path.EndsWith("/"))
                {
                    path = (path ?? "") + "index.html";
                }

                var safePath = Path.Combine(_env.WebRootPath, taskid, path);
                var fullPath = Path.GetFullPath(safePath);

                if (!fullPath.StartsWith(_env.WebRootPath, StringComparison.OrdinalIgnoreCase))
                {
                    return Forbid();
                }

                if (!System.IO.File.Exists(fullPath))
                {
                    return NotFound();
                }

                var provider = new FileExtensionContentTypeProvider();
                if (!provider.TryGetContentType(fullPath, out var mimeType))
                {
                    mimeType = "application/octet-stream"; 
                }

                return PhysicalFile(fullPath, mimeType);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    Message = "An error occurred while retrieving file.",
                    Details = ex.Message
                });
            }
        }
       
    }
}