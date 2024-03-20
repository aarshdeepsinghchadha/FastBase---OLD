using Application.Admin;
using Application.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interface.Admin
{
    /// <summary>
    /// Interface for providing administrative services related to users.
    /// </summary>
    public interface IAdminService
    {
        /// <summary>
        /// Registers a new user asynchronously.
        /// </summary>
        /// <param name="registerDto">The registration information.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the registration attempt.</returns>
        Task<ReturnResponse> RegisterUserServiceAsync(RegisterDto registerDto, string origin);

        /// <summary>
        /// Logs in a user asynchronously.
        /// </summary>
        /// <param name="loginDto">The login information.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the login attempt.</returns>
        Task<ReturnResponse> LoginUserServiceAsync(LoginDto loginDto);

        /// <summary>
        /// Refreshes the user's authentication token asynchronously.
        /// </summary>
        /// <param name="refreshTokenDto">The refresh token information.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing the refreshed token.</returns>
        Task<ReturnResponse<RefreshResponseDto>> RefreshTokenServiceAsync(RefreshTokenDto refreshTokenDto);

        /// <summary>
        /// Verifies the email address of a user asynchronously.
        /// </summary>
        /// <param name="token">The verification token.</param>
        /// <param name="email">The user's email address.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification attempt.</returns>
        Task<ReturnResponse> VerifyEmailServiceAsync(string token, string email);

        /// <summary>
        /// Initiates the process of resetting a user's forgotten password asynchronously.
        /// </summary>
        /// <param name="forgotPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        Task<ReturnResponse> ForgotPasswordServiceAsync(ForgotPasswordDto forgotPasswordDto);

        /// <summary>
        /// Resets a user's password asynchronously.
        /// </summary>
        /// <param name="resetPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        Task<ReturnResponse> ResetPasswordServiceAsync(ResetPasswordDto resetPasswordDto);

        /// <summary>
        /// Deletes a user asynchronously.
        /// </summary>
        /// <param name="authorizationToken">The user's authorization token.</param>
        /// <param name="userId">The ID of the user to be deleted.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the user deletion attempt.</returns>
        Task<ReturnResponse> DeleteUserServiceAsync(string authorizationToken, string userId);

        /// <summary>
        /// Retrieves details of a user asynchronously.
        /// </summary>
        /// <param name="authorizationToken">The user's authorization token.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of the user.</returns>
        Task<ReturnResponse<GetAllUserDto>> GetUserDetailsServiceAsync(string authorizationToken);

        /// <summary>
        /// Resends the email verification link asynchronously.
        /// </summary>
        /// <param name="resendEmailVerificationLinkDto">The information for resending the email verification link.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification link resend attempt.</returns>
        Task<ReturnResponse> ResendEmailVerificationLinkServiceAsync(ResendEmailVerificationDto resendEmailVerificationLinkDto, string origin);

        /// <summary>
        /// Retrieves details of all users asynchronously.
        /// </summary>
        /// <param name="authorizationToken">The user's authorization token.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of all users.</returns>
        Task<ReturnResponse<List<GetAllUserDto>>> GetAllUserDetailsServiceAsync(string authorizationToken);
    }

}
