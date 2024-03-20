using Application.Admin;
using Application.Common;
using Domain.Admin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interface.Token
{
    /// <summary>
    /// Interface for token-related operations.
    /// </summary>
    public interface ITokenService
    {
        /// <summary>
        /// Generates a login token asynchronously.
        /// </summary>
        /// <param name="username">The username of the user.</param>
        /// <param name="password">The user's password.</param>
        /// <returns>A string representing the generated login token.</returns>
        Task<string> GenerateLoginToken(string username, string password);

        /// <summary>
        /// Sets a refresh token for a user asynchronously.
        /// </summary>
        /// <param name="user">The user for whom the refresh token is set.</param>
        /// <param name="token">The refresh token to be set.</param>
        /// <returns>A <see cref="RefreshToken"/> representing the set refresh token.</returns>
        Task<RefreshToken> SetRefreshToken(AppUser user, string token);

        /// <summary>
        /// Decodes a token asynchronously.
        /// </summary>
        /// <param name="token">The token to be decoded.</param>
        /// <returns>A <see cref="ReturnResponse{T}"/> containing the decoded token information.</returns>
        Task<ReturnResponse<DecodeTokenDto>> DecodeToken(string token);

        /// <summary>
        /// Decodes a token for a refresh token asynchronously.
        /// </summary>
        /// <param name="token">The token to be decoded.</param>
        /// <returns>A <see cref="ReturnResponse{T}"/> containing the decoded token information.</returns>
        Task<ReturnResponse<DecodeTokenDto>> DecodeTokenForRefreshToken(string token);

        /// <summary>
        /// Generates a token for a user asynchronously.
        /// </summary>
        /// <param name="user">The user for whom the token is generated.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the token generation attempt.</returns>
        Task<ReturnResponse> GenerateToken(AppUser user);
    }

}
