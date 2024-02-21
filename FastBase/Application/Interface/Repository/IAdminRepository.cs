using Application.Admin;
using Application.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interface.Repository
{
    /// <summary>
    /// Interface for handling administrative operations related to users for handline database call
    /// </summary>
    public interface IAdminRepository
    {
        /// <summary>
        /// Registers a new user asynchronously.
        /// </summary>
        /// <param name="registerDto">The registration information.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the registration attempt.</returns>
        Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto, string origin);

        /// <summary>
        /// Logs in a user asynchronously.
        /// </summary>
        /// <param name="loginDto">The login information.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the login attempt.</returns>
        Task<ReturnResponse> LoginUserAsync(LoginDto loginDto);

        /// <summary>
        /// Refreshes the user's authentication token asynchronously.
        /// </summary>
        /// <param name="refreshTokenDto">The refresh token information.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing the refreshed token.</returns>
        Task<ReturnResponse<RefreshResponseDto>> RefreshTokenAsync(RefreshTokenDto refreshTokenDto);

        /// <summary>
        /// Verifies the email address of a user asynchronously.
        /// </summary>
        /// <param name="token">The verification token.</param>
        /// <param name="email">The user's email address.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification attempt.</returns>
        Task<ReturnResponse> VerifyEmailAsync(string token, string email);

        /// <summary>
        /// Initiates the process of resetting a user's forgotten password asynchronously.
        /// </summary>
        /// <param name="forgotPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        Task<ReturnResponse> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto);

        /// <summary>
        /// Resets a user's password asynchronously.
        /// </summary>
        /// <param name="resetPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        Task<ReturnResponse> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);

        /// <summary>
        /// Deletes a user asynchronously.
        /// </summary>
        /// <param name="userId">The ID of the user to be deleted.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the user deletion attempt.</returns>
        Task<ReturnResponse> DeleteUserAsync(string userId);

        /// <summary>
        /// Retrieves details of a user asynchronously.
        /// </summary>
        /// <param name="loggedInUserId">The ID of the logged-in user.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of the user.</returns>
        Task<ReturnResponse<GetAllUserDto>> GetUserDetailsAsync(string loggedInUserId);

        /// <summary>
        /// Resends the email verification link asynchronously.
        /// </summary>
        /// <param name="resendEmailVerificationLinkDto">The information for resending the email verification link.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification link resend attempt.</returns>
        Task<ReturnResponse> ResendEmailVerificationLinkAsync(ResendEmailVerificationDto resendEmailVerificationLinkDto, string origin);

        /// <summary>
        /// Retrieves details of all users asynchronously.
        /// </summary>
        /// <param name="loggedInUserId">The ID of the logged-in user.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of all users.</returns>
        Task<ReturnResponse<List<GetAllUserDto>>> GetAllUserDetailsAsync(string loggedInUserId);
    }

}
