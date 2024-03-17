using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Admin
{
    public class RefreshResponseDto : IValidatableObject
    {
        public string Token { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if(string.IsNullOrWhiteSpace(Token))
            {
                yield return new ValidationResult("Token is Required", new[] { nameof(Token) });
            }

            if (string.IsNullOrWhiteSpace(Username))
            {
                yield return new ValidationResult("Username is Required.", new[] { nameof(Username) });
            }

            if (string.IsNullOrWhiteSpace(Email))
            {
                yield return new ValidationResult("Email is Required.", new[] { nameof(Email)});
            }
        }
    }
}
