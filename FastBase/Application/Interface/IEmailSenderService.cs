using Application.Common;

namespace Application.Interface
{
    /// <summary>
    /// Interface for sending emails using different email services.
    /// </summary>
    public interface IEmailSenderService
    {
        /// <summary>
        /// Sends an email using the SendGrid service asynchronously.
        /// </summary>
        /// <param name="userEmail">The recipient's email address.</param>
        /// <param name="emailSubject">The subject of the email.</param>
        /// <param name="msg">The content of the email message.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email sending attempt.</returns>
        Task<ReturnResponse> SendEmailUsingSendGridAsync(string userEmail, string emailSubject, string msg);

        /// <summary>
        /// Sends an email using the MailGun service asynchronously.
        /// </summary>
        /// <param name="userEmail">The recipient's email address.</param>
        /// <param name="emailSubject">The subject of the email.</param>
        /// <param name="msg">The content of the email message.</param>
        /// <returns>A <see cref="ReturnResponse"/> indicating the result of the email sending attempt.</returns>
        Task<ReturnResponse> SendEmailUsingMailGunAsync(string userEmail, string emailSubject, string msg);
    }

}
