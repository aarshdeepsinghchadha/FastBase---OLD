using Microsoft.AspNetCore.Identity;

namespace Domain.Admin
{
    public class AppUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Role { get; set; }

        // Navigation property for one-to-many relationship
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}
