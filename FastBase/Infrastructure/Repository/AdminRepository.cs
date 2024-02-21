using Application.Admin;
using Application.Common;
using Application.Interface;
using Application.Interface.Repository;
using AutoMapper;
using Domain.Admin;
using Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Persistance;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Repository
{
    public class AdminRepository : IAdminRepository
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IResponseGeneratorService _responseGeneratorService;
        private readonly ITokenService _tokenService;
        private readonly IEmailSenderService _emailSender;
        private readonly ILogger<AdminRepository> _logger;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly DataContext _context;
        private readonly IMapper _mapper;

        public AdminRepository(IResponseGeneratorService responseGeneratorService, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ITokenService tokenService, IEmailSenderService emailSender, ILogger<AdminRepository> logger, RoleManager<IdentityRole> roleManager, DataContext context, IMapper mapper)
        {
            _responseGeneratorService = responseGeneratorService;
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _emailSender = emailSender;
            _logger = logger;
            _roleManager = roleManager;
            _context = context;
            _mapper = mapper;
        }
        /// <summary>
        /// Deletes a user asynchronously.
        /// </summary>
        /// <param name="userId">The ID of the user to be deleted.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the user deletion attempt.</returns>
        public async Task<ReturnResponse> DeleteUserAsync(string userId)
        {
            try
            {
                // Find the user by Id
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status404NotFound, "User not found.");
                }

                // Delete the user
                var result = await _userManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, "User deleted successfully.");
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status500InternalServerError, "Failed to delete user.");
                }
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during DeleteUserAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Initiates the process of resetting a user's forgotten password asynchronously.
        /// </summary>
        /// <param name="forgotPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        public async Task<ReturnResponse> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Email does not exist");
                }
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                await _emailSender.SendEmailUsingSendGridAsync(user.Email, " OTP Reset Password", "Please use the following OTP to reset your password: <br/><h3>" + token + "</h3>");
                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, "Please check your email, OTP Sent");
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during ForgotPasswordAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Retrieves details of all users asynchronously.
        /// </summary>
        /// <param name="loggedInUserId">The ID of the logged-in user.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of all users.</returns>
        public async Task<ReturnResponse<List<GetAllUserDto>>> GetAllUserDetailsAsync(string loggedInUserId)
        {
            try
            {
                // Fetch all users excluding the currently logged-in user
                var allUsers = await _userManager.Users
                    .Where(u => u.Id != loggedInUserId)
                    .ToListAsync();

                // Transform the data to DTO
                var result = allUsers.Select(user => new GetAllUserDto
                {
                    UserId = user.Id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserName = user.UserName,
                    Email = user.Email,
                    Role = user.Role,
                    EmailConfirmed = user.EmailConfirmed
                }).ToList();

                return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                    true, StatusCodes.Status200OK, "User credentials retrieved successfully", result);



               
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during GetAllUserDetailsAsync() : {ex.Message}", null);
            }
        }

        /// <summary>
        /// Retrieves details of a user asynchronously.
        /// </summary>
        /// <param name="loggedInUserId">The ID of the logged-in user.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing details of the user.</returns>
        public async Task<ReturnResponse<GetAllUserDto>> GetUserDetailsAsync(string loggedInUserId)
        {
            try
            {

                var userDetail = await _userManager.Users
                   .Where(x => x.Id == loggedInUserId)
                   .FirstOrDefaultAsync();

                if (userDetail == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetAllUserDto>(
                        false, StatusCodes.Status404NotFound, "User not found", null);
                }

                var userDto = new GetAllUserDto
                {
                    UserId = userDetail.Id,
                    FirstName = userDetail.FirstName,
                    LastName = userDetail.LastName,
                    UserName = userDetail.UserName,
                    Email = userDetail.Email,
                    Role = userDetail.Role,
                    EmailConfirmed = userDetail.EmailConfirmed
                };

                return await _responseGeneratorService.GenerateResponseAsync<GetAllUserDto>(
                    true, StatusCodes.Status200OK, "User details retrieved successfully", userDto);

            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetAllUserDto>(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during GetUserDetailsAsync() : {ex.Message}", null);
            }
        }

        /// <summary>
        /// Logs in a user asynchronously.
        /// </summary>
        /// <param name="loginDto">The login information.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the login attempt.</returns>
        public async  Task<ReturnResponse> LoginUserAsync(LoginDto loginDto)
        {
            try
            {
                // Find the user by email or username
                var user = await GetUserByEmailOrUsernameAsync(loginDto.Username);

                if (user == null)
                {
                    _logger.LogError($"Invalid username or email with {loginDto.Username}");
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status401Unauthorized, "Invalid username or email.");
                }
                if (user.EmailConfirmed == false)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status401Unauthorized, "Email not verified");
                }

                // Check if the provided password is valid
                var result = await _signInManager.CheckPasswordSignInAsync(
                    user, loginDto.Password, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    var token = await _tokenService.GenerateLoginToken(user.UserName, loginDto.Password);
                    await _tokenService.SetRefreshToken(user, token);
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, "Login successful.", token);
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status401Unauthorized, "Invalid password.");
                }
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during LoginUserAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Refreshes the user's authentication token asynchronously.
        /// </summary>
        /// <param name="refreshTokenDto">The refresh token information.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing the refreshed token.</returns>
        public async Task<ReturnResponse<RefreshResponseDto>> RefreshTokenAsync(RefreshTokenDto refreshTokenDto)
        {
            try
            {
                var response = new ReturnResponse<RefreshResponseDto>();

                var user = await _userManager.Users
                                 .Include(u => u.RefreshTokens)
                                 .SingleOrDefaultAsync(u => u.Email == refreshTokenDto.Email);

                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                           false, StatusCodes.Status401Unauthorized, "User was not Found! Unauthorized", null);
                }

                bool oldTokenExists = user.RefreshTokens.Any(x => x.Token == refreshTokenDto.OldToken);
                if (!oldTokenExists)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                        false, StatusCodes.Status401Unauthorized, "Passed Token does not Exist", null);
                }

                bool isTokenRevoked = user.RefreshTokens.Any(x => x.Token == refreshTokenDto.OldToken && x.Revoked != null);
                if (isTokenRevoked)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                        false, StatusCodes.Status401Unauthorized, "Passed Token is revoked", null);
                }


                var decodeResponse = await _tokenService.DecodeTokenForRefreshToken(refreshTokenDto.OldToken);
                if (decodeResponse.Data != null)
                {
                    if (decodeResponse.Data.Status)
                    {
                        var generateNewToken = await _tokenService.GenerateToken(user);
                        if (generateNewToken.Status)
                        {
                            var setRefreshToken = await _tokenService.SetRefreshToken(user, generateNewToken.Message);
                            var newTokenResponse = new RefreshResponseDto
                            {
                                Token = setRefreshToken.Token,
                                Email = user.Email,
                                Username = user.UserName
                            };
                            return await _responseGeneratorService.GenerateResponseAsync(
                            true, StatusCodes.Status200OK, "New Token", newTokenResponse);
                        }
                        else
                        {
                            return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                            false, StatusCodes.Status400BadRequest, generateNewToken.Message, null);
                        }
                    }
                    return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                            false, StatusCodes.Status400BadRequest, decodeResponse.Message, null);
                }
                return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                            false, StatusCodes.Status400BadRequest, "Decode Token Failed", null);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during RefreshTokenAsync() : {ex.Message}", null);
            }
        }

        /// <summary>
        /// Registers a new user asynchronously.
        /// </summary>
        /// <param name="registerDto">The registration information.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the registration attempt.</returns>
        public async Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto, string origin)
        {
            try
            {
                // Check if a user with the same email already exists
                var existingUser = await _userManager.FindByEmailAsync(registerDto.Email);
                if (existingUser != null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status400BadRequest, "User with the same email already exists.");
                }

                var roleName = await _roleManager.Roles.FirstOrDefaultAsync(x => x.Name == "User");
                // Use AutoMapper to map RegisterDto to AppUser
                var newUser = _mapper.Map<RegisterDto, AppUser>(registerDto);
                newUser.Role = roleName.Name;

                // Hash the ConfirmPassword and store it
                var passwordHasher = new PasswordHasher<AppUser>();

                // Register the user in the database
                var result = await _userManager.CreateAsync(newUser, registerDto.Password);

                if (result.Succeeded)
                {
                    var userRole = new IdentityUserRole<string>()
                    {
                        RoleId = roleName.Id,
                        UserId = newUser.Id
                    };
                    await _context.UserRoles.AddRangeAsync(userRole);
                    await _context.SaveChangesAsync();

                    var sendVerificationEmailResult = await SendVerificationEmailAsync(newUser, origin);
                    if (sendVerificationEmailResult.Status)
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(
                            true, StatusCodes.Status200OK, $"User registered successfully, Please check your mail and Verfiy your Email");
                    }
                    else
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(
                           true, StatusCodes.Status400BadRequest, $"User registered successfully, Email not sent due to some technical issues : {sendVerificationEmailResult.Message}, so please click on the ResentVerficationLink to continue, If Error Continues please contact the Support!");
                    }
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status500InternalServerError, $"Failed to register user : {result.Errors}");
                }
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during RegisterUserAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Resends the email verification link asynchronously.
        /// </summary>
        /// <param name="resendEmailVerificationLinkDto">The information for resending the email verification link.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification link resend attempt.</returns>
        public async Task<ReturnResponse> ResendEmailVerificationLinkAsync(ResendEmailVerificationDto resendEmailVerificationLinkDto, string origin)
        {
            try
            {
                //verify the email if it exist in the database or not
                var userExist = await _userManager.FindByEmailAsync(resendEmailVerificationLinkDto.Email);
                if (userExist == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, $"User Does not exist please Register!");
                }
                //if it does send email
                else
                {
                    var sendVerificationEmailResult = await SendVerificationEmailAsync(userExist, origin);
                    if (sendVerificationEmailResult.Status)
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(
                            true, StatusCodes.Status200OK, $"Please check your mail and Verfiy your Email");
                    }
                    else
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(
                           true, StatusCodes.Status400BadRequest, $"Email not sent due to some technical issues : {sendVerificationEmailResult.Message}, so please click on the ResentVerficationLink to continue, If Error Continues please contact the Support!");
                    }
                }
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during ResendEmailVerificationLinkAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Resets a user's password asynchronously.
        /// </summary>
        /// <param name="resetPasswordDto">The information for resetting the password.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the password reset attempt.</returns>
        public async Task<ReturnResponse> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Email does not exist");
                }
                if (resetPasswordDto.NewPassword != resetPasswordDto.NewConfirmPassword)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "New Password and Confirm Password should be the same.");
                }
                var isOTPVerified = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", resetPasswordDto.OTP);
                if (isOTPVerified)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var result = await _userManager.ResetPasswordAsync(user, token, resetPasswordDto.NewPassword);
                    if (result.Succeeded)
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, "Password Reset Successfully");
                    }
                    else
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Unable to Authorize User");
                    }
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Unable to Authorize User");
                }
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during ResetPasswordAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Verifies the email address of a user asynchronously.
        /// </summary>
        /// <param name="token">The verification token.</param>
        /// <param name="email">The user's email address.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email verification attempt.</returns>
        public async Task<ReturnResponse> VerifyEmailAsync(string token, string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                       false, StatusCodes.Status401Unauthorized, "Unauthorized");
                }

                var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);//decode the token as done encoding above
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);
                var result = await _userManager.ConfirmEmailAsync(user, decodedToken);//confirm if this is a valid confirmation of email and token 
                if (!result.Succeeded)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                           false, StatusCodes.Status400BadRequest, "Unable to authorize user.");
                }
                return await _responseGeneratorService.GenerateResponseAsync(
                          true, StatusCodes.Status200OK, "Email is confirmed - you can login");
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during VerifyEmailAsync() : {ex.Message}");
            }
        }

        /// <summary>
        /// Gets a user by email or username asynchronously.
        /// </summary>
        /// <param name="username">The email or username of the user to retrieve.</param>
        /// <returns>
        /// An <see cref="AppUser"/> representing the user if found; otherwise, <c>null</c>.
        /// </returns>
        private async Task<AppUser?> GetUserByEmailOrUsernameAsync(string? username)
        {
            // If the user has entered an email in the username text box
            if (!string.IsNullOrEmpty(username))
            {
                return await _userManager.FindByEmailAsync(username);
            }
            // If the user has entered a username in the username text box
            else if (!string.IsNullOrEmpty(username))
            {
                return await _userManager.FindByNameAsync(username);
            }

            return null;
        }

        /// <summary>
        /// Sends a verification email asynchronously.
        /// </summary>
        /// <param name="newUser">The user for whom the verification email is sent.</param>
        /// <param name="origin">The origin URL for email verification.</param>
        /// <returns>
        /// A <see cref="ReturnResponse"/> indicating the result of the email sending attempt.
        /// </returns>
        private async Task<ReturnResponse> SendVerificationEmailAsync(AppUser newUser, string origin)
        {
            try
            {
                // Generate email confirmation token
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                // Construct verification URL
                var encodedUrl = $"{origin}/api/admin/verifyEmail?token={token}&email={newUser.Email}";

                // Construct email message
                var message = $"<p>Please click the below link to verify your email address:</p><p><a href='{encodedUrl}'>Click to verify email</a></p>";

                // Send email using SendGrid
                var emailResult = await _emailSender.SendEmailUsingSendGridAsync(newUser.Email, "Please verify email", message);

                if (emailResult.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, $"{emailResult.Message}");
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, $"Email Not Sent: {emailResult.Message}");
                }
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, $"An Error Occurred in SendVerificationEmailAsync: {ex.Message}");
            }
        }

    }
}
