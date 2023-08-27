using System.ComponentModel.DataAnnotations;

namespace JWTAuth.DTOs
{
    public class ForgotPasswordDTO
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}
