using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Admin
{
    public class ResendEmailVerificationDto : IValidatableObject
    {
        public string Email { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(Email))
            {
                yield return new ValidationResult("Email is Required.", new[] { nameof(Email) });
            }
            else if (!IsValidEmail(Email))
            {
                yield return new ValidationResult("Invalid Email Format.", new[] { nameof(Email) });
            }
        }

        // Helper method to check email format
        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }
    }
}
