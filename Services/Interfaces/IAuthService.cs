using JWTAuth.DTOs;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Services.Interfaces
{
    public interface IAuthService
    {
        public Task<AuthResult> UserRegister(UserRegistrationRequestDTO userRegistrationRequestDTO);
        public Task<AuthResult> UserLogin(UserLoginRequestDTO userLoginRequest);
        public Task<AuthResult> UserLoginWithTwoFA(string userEmail, string twoFACode);
        public Task<AuthResult> ConfirmUserEmail(string userId, string code);
        public Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest);
        public Task<AuthResult> GenerateJWTToken(IdentityUser user);
        public Task<AuthResult> ForgotPasswordAsync(string email);
        public Task<AuthResult> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO);
        public Task<AuthResult> CustomSignOutUser(string userId, string refreshToken);
        public Task<bool> CheckUserLoggedInStatus(string user);
        public Task<AuthResult> SignOutUser();
        public string RandomStringGenerate(int len);
        public DateTime UtcTimeStampToDateTime(long utcExpiryDate);
        public string GetResetPasswordHtmlBody(string link);
    }
}
