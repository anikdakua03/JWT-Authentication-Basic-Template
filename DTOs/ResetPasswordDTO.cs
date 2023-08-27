using System.ComponentModel.DataAnnotations;

namespace JWTAuth.DTOs
{
    public class ResetPasswordDTO
    {
        [Required]
        public string? Token { get; set; }

        [Required]
        [EmailAddress]
        public string? Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string? NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmed password do not match.")]
        public string? ConfirmPassword { get; set; }

    }
}
