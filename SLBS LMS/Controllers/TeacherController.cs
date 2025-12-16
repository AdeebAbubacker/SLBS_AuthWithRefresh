
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LMS.WebApi.Controllers
{
    [ApiController]
    [Route("api/teacher")]
    [Authorize(Roles = "Teacher")]
    public class TeacherController : ControllerBase
    {
        [HttpGet("courses")]
        public IActionResult Courses() => Ok("Teacher courses");
    }
}
