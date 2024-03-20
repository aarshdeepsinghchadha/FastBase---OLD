using Application.Admin;
using Application.Interface.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    /// <summary>
    /// Controller responsible for handling administrative tasks.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly IAdminService _adminService;

        /// <summary>
        /// Initializes a new instance of the <see cref="AdminController"/> class.
        /// </summary>
        /// <param name="adminService">The admin service.</param>
        public AdminController(IAdminService adminService)
        {
            _adminService = adminService;
        }

        /// <summary>
        /// Authenticates a user and generates a JWT token.
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var result = await _adminService.LoginUserServiceAsync(loginDto);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Registers a new user.
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            string? origin = Request.Headers["origin"];
            if (origin != null)
            {
                var result = await _adminService.RegisterUserServiceAsync(registerDto, origin);
                return StatusCode(result.StatusCode, result);
            }
            else
            {
                return StatusCode(StatusCodes.Status404NotFound, "Please Pass the Origin from Headers");
            }
        }

        /// <summary>
        /// Refreshes the JWT token for a user.
        /// </summary>
        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
        {
            var result = await _adminService.RefreshTokenServiceAsync(refreshTokenDto);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Verifies the email of a user.
        /// </summary>
        [AllowAnonymous]
        [HttpGet("VerifyEmail")]
        public async Task<IActionResult> VerifyEmail([FromQuery(Name = "token")] string token, [FromQuery(Name = "email")] string email)
        {
            var result = await _adminService.VerifyEmailServiceAsync(token, email);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Resets the password for a user.
        /// </summary>
        [HttpPost("resetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var result = await _adminService.ResetPasswordServiceAsync(resetPasswordDto);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Initiates the process of recovering a forgotten password.
        /// </summary>
        [HttpPost("forgotPassword")]
        public async Task<IActionResult> ForgorPassword(ForgotPasswordDto forgotPasswordDto)
        {
            var result = await _adminService.ForgotPasswordServiceAsync(forgotPasswordDto);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Resends the email verification link to a user.
        /// </summary>
        [HttpPost("resendEmailVerificationLink")]
        public async Task<IActionResult> ResendEmailVerficationLink(ResendEmailVerificationDto resendEmailVerificationDto)
        {
            string? origin = Request.Headers["origin"];
            if (origin != null)
            {
                var result = await _adminService.ResendEmailVerificationLinkServiceAsync(resendEmailVerificationDto, origin);
                return StatusCode(result.StatusCode, result);
            }
            else
            {
                return StatusCode(StatusCodes.Status404NotFound, "Please Pass the Origin from Headers");
            }
        }

        /// <summary>
        /// Deletes a user with the specified ID.
        /// </summary>
        [Authorize]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser([FromHeader(Name = "Authorization")] string authorizationToken, string id)
        {
            var result = await _adminService.DeleteUserServiceAsync(authorizationToken, id);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Retrieves details of the authenticated user.
        /// </summary>
        [Authorize]
        [HttpGet("getUserDetails")]
        public async Task<IActionResult> GetUser([FromHeader(Name = "Authorization")] string authorizationToken)
        {
            var result = await _adminService.GetUserDetailsServiceAsync(authorizationToken);
            return StatusCode(result.StatusCode, result);
        }

        /// <summary>
        /// Retrieves details of all users with credentials.
        /// </summary>
        [Authorize(Roles = "Administrator")]
        [HttpGet("getAllUserDetails")]
        public async Task<IActionResult> GetAllUserWithCreds([FromHeader(Name = "Authorization")] string authorizationToken)
        {
            var result = await _adminService.GetAllUserDetailsServiceAsync(authorizationToken);
            return StatusCode(result.StatusCode, result);
        }
    }

}
