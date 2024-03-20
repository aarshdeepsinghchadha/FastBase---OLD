using Application.Admin;
using Application.Common;
using Application.Interface.Admin;
using Application.Interface.Core;
using Application.Interface.Repository;
using Application.Interface.Token;
using Domain.Admin;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Persistance;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Services.Admin
{
    public class AdminService : IAdminService
    {

        private readonly ITokenService _tokenService;
        private readonly IAdminRepository _adminRepository;
        private readonly IResponseGeneratorService _responseGeneratorService;

        public AdminService(ITokenService tokenService, IAdminRepository adminRepository, IResponseGeneratorService responseGeneratorService)
        {
            _tokenService = tokenService;
            _adminRepository = adminRepository;
            _responseGeneratorService = responseGeneratorService;
        }

        /// <summary>
        /// Logs in a user asynchronously.
        /// </summary>
        /// <param name="loginDto">The login information.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the login attempt.</returns>
        public async Task<ReturnResponse> LoginUserServiceAsync(LoginDto loginDto)
        {
            try
            {
                if (loginDto == null)
                {
                    await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please enter Login details!");
                }
                else if (loginDto.Username == null || loginDto.Password == null)
                {
                    await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please check your passed username and password, re-enter it again!");
                }

                ReturnResponse result = await _adminRepository.LoginUserAsync(loginDto);
                return result;

            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user login : {ex.Message}");
            }
        }

        /// <summary>
        /// Registers a new user asynchronously.
        /// </summary>
        /// <param name="registerDto">The registration information.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the registration attempt.</returns>
        public async Task<ReturnResponse> RegisterUserServiceAsync(RegisterDto registerDto, string origin)
        {
            try
            {
                // Check if password and confirmPassword match
                if (registerDto.Password != registerDto.ConfirmPassword)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status400BadRequest, "Password and confirm password do not match.");
                }

                ReturnResponse result = await _adminRepository.RegisterUserAsync(registerDto, origin);
                return result;

            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user registration: {ex.Message}");
            }
        }

        /// <summary>
        /// Deletes a user asynchronously.
        /// </summary>
        /// <param name="authorizationToken">The user's authorization token.</param>
        /// <param name="userId">The ID of the user to be deleted.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the user deletion attempt.</returns>
        public async Task<ReturnResponse> DeleteUserServiceAsync(string authorizationToken, string userId)
        {
            try
            {
                //check the authorization token is valid or not
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authorizationToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                else if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }

                ReturnResponse result = await _adminRepository.DeleteUserAsync(userId);
                return result;
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user deletion, {ex.Message}");
            }
        }

        /// <summary>
        /// Refreshes the user's authentication token asynchronously.
        /// </summary>
        /// <param name="refreshTokenDto">The refresh token information.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing the refreshed token.</returns>
        public async Task<ReturnResponse<RefreshResponseDto>> RefreshTokenServiceAsync(RefreshTokenDto refreshTokenDto)
        {
            if (refreshTokenDto == null)
            {
                await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please pass the details to refresh token");
            }
            else if (refreshTokenDto.OldToken == null || refreshTokenDto.Email == null)
            {
                await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please pass the details the required information to refresh the token");
            }

            ReturnResponse<RefreshResponseDto> result = await _adminRepository.RefreshTokenAsync(refreshTokenDto);
            return result;

        }

        /// <summary>
        /// Verifies the email address of a user asynchronously.
        /// </summary>
        /// <param name="token">The verification token.</param>
        /// <param name="email">The user's email address.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification attempt.</returns>
        public async Task<ReturnResponse> VerifyEmailServiceAsync(string token, string email)
        {
            try
            {
                ReturnResponse result = await _adminRepository.VerifyEmailAsync(token, email);
                return result;
            }
            catch (Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user login : {ex.Message}");
            }
        }

        /// <summary>
        /// Initiates the process of resetting a user's forgotten password asynchronously.
        /// </summary>
        /// <param name="forgotPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        public async Task<ReturnResponse> ForgotPasswordServiceAsync(ForgotPasswordDto forgotPasswordDto)
        {
            try
            {
                ReturnResponse result = await _adminRepository.ForgotPasswordAsync(forgotPasswordDto);
                return result;
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        /// <summary>
        /// Resets a user's password asynchronously.
        /// </summary>
        /// <param name="resetPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        public async Task<ReturnResponse> ResetPasswordServiceAsync(ResetPasswordDto resetPasswordDto)
        {
            try
            {
                if (resetPasswordDto == null)
                {
                    await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please pass the details to reset the password");
                }
                else if (resetPasswordDto.NewPassword == null || resetPasswordDto.NewConfirmPassword == null || resetPasswordDto.OTP == null || resetPasswordDto.Email == null)
                {
                    await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please recheck and pass the details to refresh token");
                }
                ReturnResponse result = await _adminRepository.ResetPasswordAsync(resetPasswordDto);
                return result;

            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        /// <summary>
        /// Resends the email verification link asynchronously.
        /// </summary>
        /// <param name="resendEmailVerificationLinkDto">The information for resending the email verification link.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification link resend attempt.</returns>
        public async Task<ReturnResponse> ResendEmailVerificationLinkServiceAsync(ResendEmailVerificationDto resendEmailVerificationLinkDto, string origin)
        {
            try
            {
                if (resendEmailVerificationLinkDto.Email == null)
                {
                    await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Please pass the email");
                }
                ReturnResponse result = await _adminRepository.ResendEmailVerificationLinkAsync(resendEmailVerificationLinkDto, origin);
                return result;
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, $"An Error occured in ResendEmailVerificationLinkServiceAsync() , {ex.Message}");
            }
        }

        /// <summary>
        /// Retrieves details of a user asynchronously.
        /// </summary>
        /// <param name="authorizationToken">The user's authorization token.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of the user.</returns>
        public async Task<ReturnResponse<GetAllUserDto>> GetUserDetailsServiceAsync(string authorizationToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authorizationToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetAllUserDto>(
                        false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetAllUserDto>(
                        false, StatusCodes.Status401Unauthorized, "Invalid token", null);
                }
                ReturnResponse<GetAllUserDto> result = await _adminRepository.GetUserDetailsAsync(checkAuthorizationTokenIsValid.Data.UserDetails.Id);
                return result;

            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetAllUserDto>(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred while retrieving user details: {ex.Message}", null);
            }
        }

        /// <summary>
        /// Retrieves details of all users asynchronously.
        /// </summary>
        /// <param name="authorizationToken">The user's authorization token.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of all users.</returns>
        public async Task<ReturnResponse<List<GetAllUserDto>>> GetAllUserDetailsServiceAsync(string authorizationToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authorizationToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                        false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                else if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                        false, StatusCodes.Status401Unauthorized, "Invalid token", null);
                }

                ReturnResponse<List<GetAllUserDto>> result = await _adminRepository.GetAllUserDetailsAsync(checkAuthorizationTokenIsValid.Data.UserDetails.Id);
                return result;
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred in GetAllUserDetailsServiceAsync(): {ex.Message}", null);
            }
        }
    }
}
