using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Services.Interfaces
{
    public interface IEmailService
    {
        //Task<IdentityUser> CreateUserAsync(UserRegistrationRequestDTO userRegistrationRequestDTO);
        Task<string> SendMailAsync(MailRequest mailRequest);
        string GetHtmlBody();
        Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest);
        Task<AuthResult> GenerateJWTToken(IdentityUser user);
        string RandomStringGenerate(int len);
        DateTime UtcTimeStampToDateTime(long utcExpiryDate);
        Task<AuthResult> ForgotPasswordAsync(string email, string baseUrl);
        public string GetResetPasswordHtmlBody(string resetLink);
        Task<AuthResult> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO);
    }
}
