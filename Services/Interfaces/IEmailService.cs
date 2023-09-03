using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Services.Interfaces
{
    public interface IEmailService
    {
        //Task<IdentityUser> CreateUserAsync(UserRegistrationRequestDTO userRegistrationRequestDTO);
        public Task<string> SendMailAsync(MailRequest mailRequest);
        public string GetHtmlBody();
        public Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest);
        public Task<AuthResult> GenerateJWTToken(IdentityUser user);
        string RandomStringGenerate(int len);
        public DateTime UtcTimeStampToDateTime(long utcExpiryDate);
        public Task<AuthResult> ForgotPasswordAsync(string email, string baseUrl);
        public string GetResetPasswordHtmlBody(string resetLink);
        public Task<AuthResult> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO);
        public Task<AuthResult> SignOutUser();
        public Task<AuthResult> CustomSignOutUser(string userId, string refreshToken);
        public Task<AuthResult> CheckUserLoggedInStatus(string user);
    }
}
