using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

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
        public async Task<IActionResult> Get(string taskid, string path = "index.html")
        {
            if (string.IsNullOrEmpty(path) || path.EndsWith("/"))
                path = path??""+"index.html";

            var filePath = Path.Combine(_env.WebRootPath, taskid, path);

            if (!filePath.StartsWith(_env.WebRootPath) || !System.IO.File.Exists(filePath))
                return NotFound();

            var mimeType = GetMimeType(Path.GetExtension(filePath));
            return PhysicalFile(filePath, mimeType);
        }

        private string GetMimeType(string extension)
        {
            return extension.ToLower() switch
            {
                ".css" => "text/css",
                ".js" => "application/javascript",
                ".html" => "text/html",
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".woff" => "font/woff",
                ".woff2" => "font/woff2",
                ".svg" => "image/svg+xml",
                ".json" => "application/json",
                _ => "application/octet-stream"
            };
        }
    }
}