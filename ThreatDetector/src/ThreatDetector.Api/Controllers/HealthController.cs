using Microsoft.AspNetCore.Mvc;

namespace ThreatDetector.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class HealthController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    public HealthController(IWebHostEnvironment env)
    {
        _env = env;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new
        {
            status = "healthy",
            environment = _env.EnvironmentName,
            timestamp = DateTime.UtcNow,
            version = "0.1.0",
        });
    }
}
