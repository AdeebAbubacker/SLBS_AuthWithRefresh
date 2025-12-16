using Microsoft.AspNetCore.Identity;

namespace SLBS_LMS.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }

        public IdentityUser User { get; set; }
    }
}
