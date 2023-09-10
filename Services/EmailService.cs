using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using JWTAuth.Services.Interfaces;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MimeKit;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuth.Data;
using System.Data;

namespace JWTAuth.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _emailSettings;
        private readonly IConfiguration _configuration;
        public EmailService(IOptions<EmailSettings> emailSettings,IConfiguration configuration)
        {
            _emailSettings = emailSettings.Value;
            _configuration = configuration;
        }

        // Sending mail
        public async Task<AuthResult> SendMailAsync(IdentityUser user, string confirmationCode)
        {
            var email = new MimeMessage();
            var subject = "Test mail from my one of the project ";

            var emailBody = GetHtmlBody();

            var callbackURL = string.Format((_configuration.GetSection("AppSettings:APIURL").Value
                                    + _configuration.GetSection("AppSettings:ConfirmEmail").Value ),
                                    user.Id, confirmationCode);

            // now encoding the email body bcs in code , there may be # ^ escape char , which may affect the url
            var replacedBody = emailBody.Replace("#URL#", callbackURL);

            // sent this email from that email client
            MailRequest mailRequest = new MailRequest()
            {
                ToMail = user.Email,
                Subject = subject,
                Body = replacedBody
            };

            email.Sender = MailboxAddress.Parse(_emailSettings.FromEmail);
            email.To.Add(MailboxAddress.Parse(mailRequest.ToMail));
            email.Subject = mailRequest.Subject;

            var builder = new BodyBuilder();
            builder.HtmlBody = mailRequest.Body;
            email.Body = builder.ToMessageBody();

            var smtpClient = new SmtpClient();
            // connect and validate
            smtpClient.Connect(_emailSettings.Host, _emailSettings.Port, SecureSocketOptions.StartTls);
            smtpClient.Authenticate(_emailSettings.FromEmail, _emailSettings.Password);
            // then send
            var res = await smtpClient.SendAsync(email);
            // after that must close the connection
            smtpClient.Disconnect(true);

            if (res != null)
            {
                return new AuthResult()
                {
                    Result = true,
                    Token = "",
                    RefreshToken = "",
                    Message = "Please verify your email , just sent to you."
                };
            }

            return new AuthResult()
            {
                Result = false,
                Message = "Cannot send email !!"
            };
        }

        public string GetHtmlBody()
        {
            string emailBody = "<h1>Welcome to Authentication</h1>";
            emailBody += "Please confirm your email !!<a href=\"#URL#\"> <strong>Click here</strong> </a>";
            emailBody += "<div style=\"width:100%;background-color:lightblue;text-align:center;margin:10px\">";
            emailBody += "</div>";
            return emailBody;
        }

        public string GetResetPasswordHtmlBody(string link)
        {
            string emailBody = "<h1> Reset your password </h1>";
            emailBody += $"Please use the link to reset !!<a href=\"{link}\"> <strong>Click here</strong> </a>";
            emailBody += "<div style=\"width:100%;background-color:lightblue;text-align:center;margin:10px\">";
            emailBody += "</div>";
            return emailBody;
        }

        public async Task<AuthResult> Send2FAMailAsync(IdentityUser user, string code)
        {
            var email = new MimeMessage();
            var subject = "Two factor authentication code ";

            var emailBody = $"<h1> Here is your two factor authentication code : {code} </h1>";

            // sent this email from that email client
            MailRequest mailRequest = new MailRequest()
            {
                ToMail = user.Email,
                Subject = subject,
                Body = emailBody
            };

            email.Sender = MailboxAddress.Parse(_emailSettings.FromEmail);
            email.To.Add(MailboxAddress.Parse(mailRequest.ToMail));
            email.Subject = mailRequest.Subject;

            var builder = new BodyBuilder();
            builder.HtmlBody = mailRequest.Body;
            email.Body = builder.ToMessageBody();

            var smtpClient = new SmtpClient();
            // connect and validate
            smtpClient.Connect(_emailSettings.Host, _emailSettings.Port, SecureSocketOptions.StartTls);
            smtpClient.Authenticate(_emailSettings.FromEmail, _emailSettings.Password);
            // then send
            var res = await smtpClient.SendAsync(email);
            // after that must close the connection
            smtpClient.Disconnect(true);

            if (res != null)
            {
                return new AuthResult()
                {
                    Result = true,
                    Token = "",
                    RefreshToken = "",
                    Message = "Please check your email for two factor authentication code, just sent to you."
                };
            }

            return new AuthResult()
            {
                Result = false,
                Message = "Cannot send email !!"
            };
        }
    }
}
