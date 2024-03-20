using Application.Admin;
using Application.Common;
using Application.Interface.Core;
using Application.Interface.Token;
using Domain.Admin;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Persistance;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Infrastructure.Services.Token
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IResponseGeneratorService _responseGeneratorService;
        private readonly DataContext _context;
        public TokenService(UserManager<AppUser> userManager, IConfiguration configuration, IResponseGeneratorService responseGeneratorService, DataContext context)
        {
            _userManager = userManager;
            _configuration = configuration;
            _responseGeneratorService = responseGeneratorService;
            _context = context;
        }


        /// <summary>
        /// Generates a login token asynchronously.
        /// </summary>
        /// <param name="username">The username of the user.</param>
        /// <param name="password">The user's password.</param>
        /// <returns>A string representing the generated login token.</returns>
        public async Task<string> GenerateLoginToken(string username, string password)
        {
            var user = await _userManager.FindByNameAsync(username);

            if (user == null || !await _userManager.CheckPasswordAsync(user, password))
            {
                throw new Exception("The Username or password is incorrect");
            }
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
                // Add any additional claims as needed
            };

            var jwtSecret = _configuration["Jwt:Secret"];
            var jwtExpirationInMinutes = Convert.ToInt32(_configuration["Jwt:ExpirationInMinutes"]);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(jwtExpirationInMinutes),
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.WriteToken(token);

            return jwtToken;
        }
        /// <summary>
        /// Sets a refresh token for a user asynchronously.
        /// </summary>
        /// <param name="user">The user for whom the refresh token is set.</param>
        /// <param name="token">The refresh token to be set.</param>
        /// <returns>A <see cref="RefreshToken"/> representing the set refresh token.</returns>
        public async Task<RefreshToken> SetRefreshToken(AppUser user, string token)
        {
            try
            {
                if (user == null)
                {
                    throw new ArgumentNullException(nameof(user), "User cannot be null");
                }

                // Expire all existing tokens for the user
                await ExpireExistingTokensAsync(user.Id);

                var expirationInMinutes = Convert.ToInt32(_configuration["Jwt:ExpirationInMinutes"]);
                var expirationDateTime = DateTime.UtcNow.AddMinutes(expirationInMinutes);

                RefreshToken refreshToken = new RefreshToken
                {
                    Token = token,
                    AppUserId = user.Id,
                    Expires = expirationDateTime
                };

                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);

                //var cookieOptions = new CookieOptions
                //{
                //    HttpOnly = true, // not accessible via JavaScript
                //    Expires = expirationDateTime
                //};

                return refreshToken;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// Expires all existing refresh tokens for a user asynchronously.
        /// </summary>
        /// <param name="appUserId">The ID of the user for whom the tokens should be expired.</param>
        /// <remarks>
        /// This method retrieves all refresh tokens for the specified user from the database
        /// and revokes each token by setting the 'Revoked' property to the current UTC time.
        /// </remarks>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        private async Task ExpireExistingTokensAsync(string appUserId)
        {
            // Retrieve the user from the database
            var user = await _userManager.FindByIdAsync(appUserId);

            if (user != null)
            {
                // Retrieve all tokens for the user from the database
                var existingTokens = await _context.RefreshTokens
                    .Where(x => x.AppUserId == user.Id && x.Revoked == null)
                    .ToListAsync();

                // Iterate through the existing tokens and revoke them
                foreach (var existingToken in existingTokens)
                {
                    existingToken.Revoked = DateTime.UtcNow;
                }

                // Save changes to the database
                await _context.SaveChangesAsync();
            }
        }


        /// <summary>
        /// Decodes a token for a refresh token asynchronously.
        /// </summary>
        /// <param name="token">The token to be decoded.</param>
        /// <returns>A <see cref="ReturnResponse{T}"/> containing the decoded token information.</returns>
        public async Task<ReturnResponse<DecodeTokenDto>> DecodeTokenForRefreshToken(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status401Unauthorized, "Please Login and pass the token", null);
                }

                // Remove "Bearer " prefix from the token, if present
                token = token?.Replace("Bearer ", string.Empty);

                // Decode and validate the JWT token
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtSecret = _configuration["Jwt:Secret"];
                var key = Encoding.UTF8.GetBytes(jwtSecret);
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false // Do not validate token lifetime
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                // Extract user information from the decoded token
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;

                // Check if the user exists
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status404NotFound, "User does not exist", null);
                }

                var response = new DecodeTokenDto
                {
                    Status = true
                };
                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, "ValidToken", response);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status500InternalServerError, ex.Message, null);
            }
        }

        /// <summary>
        /// Decodes a token asynchronously.
        /// </summary>
        /// <param name="token">The token to be decoded.</param>
        /// <returns>A <see cref="ReturnResponse{T}"/> containing the decoded token information.</returns>
        public async Task<ReturnResponse<DecodeTokenDto>> DecodeToken(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status401Unauthorized, "Please Login and pass the token", null);
                }

                // Remove "Bearer " prefix from the token, if present
                token = token?.Replace("Bearer ", string.Empty);

                // Decode and validate the JWT token
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtSecret = _configuration["Jwt:Secret"];
                var key = Encoding.UTF8.GetBytes(jwtSecret);
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true, // Enable token lifetime validation
                    ClockSkew = TimeSpan.Zero // No tolerance for expired tokens
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                // Extract user information from the decoded token
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;

                // Check if the user exists
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status404NotFound, "User does not exist", null);
                }
                var existingToken = await _context.RefreshTokens.Where(x => x.AppUserId == user.Id && x.Token == token).FirstOrDefaultAsync();
                if (existingToken == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status404NotFound, "Token does not exist", null);
                }
                // Check if the token is expired
                if (validatedToken.ValidTo < DateTime.UtcNow || existingToken.Revoked != null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status400BadRequest, "Token has expired", null);
                }
                var response = new DecodeTokenDto
                {
                    Status = true,
                    UserDetails = user
                };
                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, "ValidToken", response);
            }
            catch (SecurityTokenExpiredException)
            {
                return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status400BadRequest, "Token has expired", null);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status500InternalServerError, ex.Message, null);
            }
        }

        /// <summary>
        /// Generates a token for a user asynchronously.
        /// </summary>
        /// <param name="user">The user for whom the token is generated.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the token generation attempt.</returns>
        public async Task<ReturnResponse> GenerateToken(AppUser user)
        {
            try
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, user.Role)
                    // Add any additional claims as needed
                };

                var jwtSecret = _configuration["Jwt:Secret"];
                var jwtExpirationInMinutes = Convert.ToInt32(_configuration["Jwt:ExpirationInMinutes"]);

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    audience: _configuration["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(jwtExpirationInMinutes),
                    signingCredentials: credentials
                );

                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.WriteToken(token);

                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, jwtToken);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}
