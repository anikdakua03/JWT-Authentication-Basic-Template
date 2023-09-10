using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Services.Interfaces
{
    public interface IEmailService
    {
        public Task<AuthResult> SendMailAsync(IdentityUser user, string confirmationCode);
        public string GetHtmlBody();
        public string GetResetPasswordHtmlBody(string resetLink);
        public Task<AuthResult> Send2FAMailAsync(IdentityUser user, string confirmationCode);
    }
}
