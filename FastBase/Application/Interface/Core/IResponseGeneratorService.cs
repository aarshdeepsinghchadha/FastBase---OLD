using Application.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interface.Core
{
    /// <summary>
    /// Interface for generating response objects based on the provided parameters.
    /// </summary>
    public interface IResponseGeneratorService
    {
        /// <summary>
        /// Generates a response asynchronously without additional data.
        /// </summary>
        /// <param name="status">The status indicating the success or failure of the operation.</param>
        /// <param name="statusCode">The HTTP status code to be included in the response.</param>
        /// <param name="message">The message to be included in the response.</param>
        /// <returns>A <see cref="ReturnResponse"/> containing the generated response.</returns>
        Task<ReturnResponse> GenerateResponseAsync(bool status, int statusCode, string message);

        /// <summary>
        /// Generates a response asynchronously with additional data.
        /// </summary>
        /// <typeparam name="T">The type of additional data to be included in the response.</typeparam>
        /// <param name="status">The status indicating the success or failure of the operation.</param>
        /// <param name="statusCode">The HTTP status code to be included in the response.</param>
        /// <param name="message">The message to be included in the response.</param>
        /// <param name="data">The additional data to be included in the response.</param>
        /// <returns>A <see cref="ReturnResponse{T}"/> containing the generated response with additional data.</returns>
        Task<ReturnResponse<T>> GenerateResponseAsync<T>(bool status, int statusCode, string message, T data);
    }

}
