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
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _appDbContext;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        public EmailService(IOptions<EmailSettings> emailSettings, UserManager<IdentityUser> userManager, TokenValidationParameters tokenValidationParameters, AppDbContext
             appDbContext, IConfiguration configuration, SignInManager<IdentityUser> signInManager)
        {
            _emailSettings = emailSettings.Value;
            _userManager = userManager;
            _tokenValidationParameters = tokenValidationParameters;
            _appDbContext = appDbContext;
            _configuration = configuration;
            _signInManager = signInManager;
        }


        // Sending mail
        public async Task<string> SendMailAsync(MailRequest mailRequest)
        {
            var email = new MimeMessage();

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

            return res;
        }

        public string GetHtmlBody()
        {
            string emailBody = "<h1>Welcome to Authentication</h1>";
            emailBody += "Please confirm your email !!<a href=\"#URL#\"> <strong>Click here</strong> </a>";
            emailBody += "<div style=\"width:100%;background-color:lightblue;text-align:center;margin:10px\">";
            emailBody += "</div>";
            return emailBody;
        }

        public async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenhandler = new JwtSecurityTokenHandler();

            try
            {
                _tokenValidationParameters.ValidateLifetime = true; // for local dev only false

                var tokenInVerification = jwtTokenhandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                // different types of validation with different rules
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    // will validate againsted the actual jwt token tokens creation algorithms
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (!result) return null!; // invalid or not matching
                }

                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(a => a.Type == JwtRegisteredClaimNames.Exp)!.Value);

                var expiryDate = UtcTimeStampToDateTime(utcExpiryDate);

                if (DateTime.UtcNow < expiryDate)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Hey !! your Refresh token hasn't expired yet !!"
                        }
                    };
                }
                // now compared with stored token in db
                var storedToken = await _appDbContext.RefreshTokens.FirstOrDefaultAsync(a => a.Token == tokenRequest.RefreshToken);
                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "There is no refresh token !!"
                        }
                    };
                }
                // currently token is used or not
                if (storedToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Refresh token in use !!"
                        }
                    };
                }
                // checking that if it is already revoked or not
                if (storedToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Refresh token revoked !!"
                        }
                    };
                }
                // matching with stored token id
                var jwtTokenId = tokenInVerification.Claims.FirstOrDefault(a => a.Type == JwtRegisteredClaimNames.Jti)!.Value;
                if (jwtTokenId != storedToken.JWTId)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid token !!"
                        }
                    };
                }
                // if the stored token has expired or not
                if (DateTime.UtcNow > storedToken.ExpiryDate)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Token has expired !!"
                        }
                    };
                }
                // now after all validation can create new refresh token also if it is in used by the user
                storedToken.IsUsed = true;
                _appDbContext.RefreshTokens.Update(storedToken);
                await _appDbContext.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId!);
                var tokenCreation = await GenerateJWTToken(dbUser!);

                return tokenCreation;
            }
            catch (Exception e)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Some error occured !!",
                        $"Error  message from server :-> {e.Message}"
                    }
                };
            }
        }

        public async Task<AuthResult> GenerateJWTToken(IdentityUser user)
        {
            var jwtTokenhandler = new JwtSecurityTokenHandler();

            // get that secret encoded in array of bytes
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value!);

            // check user roles
            //var userRoles = await _userManager.GetRolesAsync(user);

            //  descripting the token where mentioning those 3 parts of JWT token
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    // add claims as you want
                    new Claim("id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToLocalTime().ToString()),
                }),
                Issuer = _configuration.GetSection("JwtConfig:Audience").Value!,
                Audience = _configuration.GetSection("JwtConfig:Audience").Value!,
                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value!)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            
            var newToken = jwtTokenhandler.CreateToken(tokenDescriptor);
            var newJWTToken = jwtTokenhandler.WriteToken(newToken); // this serializes a JWT Security token into a JWT int compact serialization format

            // create new refresh token
            var refreshToken = new RefreshToken()
            {
                UserId = user.Id,
                JWTId = newToken.Id,
                Token = RandomStringGenerate(25), // have to attach refresh token
                IsUsed = false,
                IsRevoked = false,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddDays(1),
                IsSignedIn = true
            };
            // now save this refresh token to refresh token database
            if (refreshToken != null) await _appDbContext.RefreshTokens.AddAsync(refreshToken);
            else
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Refresh token can not be null , hence cannot add in to db !!"
                    },
                };
            }
            var dbUserRole = await _userManager.GetRolesAsync(user!);
            await _appDbContext.SaveChangesAsync();

            var result = new AuthResult()
            {
                Result = true,
                RefreshToken = refreshToken.Token, // attaching also the refresh token 
                Token = newJWTToken,
                Message = "Logged in successfully but your 2 factor authentication hasn't set up, please set up !!",
                Roles = new List<string>(dbUserRole)
            };
            return result;
        }

        // will help creating random refresh toekn as per our logic
        public string RandomStringGenerate(int len)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_";

            var myString = new string(Enumerable.Repeat(chars, len).Select(a => a[random.Next(a.Length)]).ToArray());

            return myString;
        }

        // this will convert seconds to a foramttable year:month:day:hour:minutes:seconds:miliseconds
        public DateTime UtcTimeStampToDateTime(long utcExpiryDate)
        {
            var dateTimeValue = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeValue = dateTimeValue.AddSeconds(utcExpiryDate).ToLocalTime();
            return dateTimeValue;
        }

        // forgot password
        public async Task<AuthResult> ForgotPasswordAsync(string email, string baseUrl)
        {
            // check email already exists or not
            if (email == null) // means email exists
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Please provide valid email !!"
                    }
                }; // or we can also create custom exceptions 
            }
            var existed_user = await _userManager.FindByEmailAsync(email); // adding! because this will prevent any null value

            if (existed_user == null) // means email exists
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Cannot find you !!"
                    }
                }; // or we can also create custom exceptions 
            }

            var newToken = await _userManager.GeneratePasswordResetTokenAsync(existed_user!);

            // generate a URl for password reset link
            
            var resetLink = $"{baseUrl}/api/Authentication/ResetPassword?Email={email}&token={newToken}";
            // now encoding the email body bcs in code , there may be # ^ escape char , which may affect the url
            // send to the user
            MailRequest resetMailRequest = new MailRequest()
            {
                ToMail = email,
                Subject = "Reset your password !",
                Body = GetResetPasswordHtmlBody(resetLink)
            };
            await SendMailAsync(resetMailRequest);

            return new AuthResult
            {
                Token = newToken,
                Result = true,
                Errors = new List<string>()
                {
                    "Reset password link sent successfully !!"
                }
            };
        }

        public string GetResetPasswordHtmlBody(string link)
        {
            string emailBody = "<h1> Reset your password </h1>";
            emailBody += $"Please use the link to reset !!<a href=\"{link}\"> <strong>Click here</strong> </a>";
            emailBody += "<div style=\"width:100%;background-color:lightblue;text-align:center;margin:10px\">";
            emailBody += "</div>";
            return emailBody;
        }

        public async Task<AuthResult> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO)
        {
            var existed_user = await _userManager.FindByEmailAsync(resetPasswordDTO.Email!); // adding! because this will prevent any null value

            if (existed_user == null) // means invalid
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Cannot find you !!"
                    }
                }; // or we can also create custom exceptions 
            }

            var result = await _userManager.ResetPasswordAsync(existed_user!, resetPasswordDTO.Token!, resetPasswordDTO.NewPassword!);

            if(!result.Succeeded) 
            {
                return new AuthResult()
                {
                    Result = false,
                    Message = "Some error occured , please try after sometime !",
                    Errors = result.Errors.Select(a => a.Description).ToList()
                };
            }

            // send to the user conveying taht password reset successfully
            MailRequest resetMailRequest = new MailRequest()
            {
                ToMail = resetPasswordDTO.Email,
                Subject = "Password changed successfully !!",
                Body = "<h1> Your password changed successfully !"
            };
            await SendMailAsync(resetMailRequest);
            return new AuthResult()
            {
                Result = true,
                Message = "Password changed successfully "
            }; ;
        }

        public async Task<AuthResult> SignOutUser()
        {
            await _signInManager.SignOutAsync();

            return new AuthResult()
            {
                Result = true,
                Message = "User logged out successfully !!"
            };
        }

        public async Task<AuthResult> CustomSignOutUser(string user , string refreshToken)
        {
            // if isSignedin false means user not logged in
            var userId = await _userManager.FindByEmailAsync(user); 
            var checkUserStatus =  _appDbContext.RefreshTokens.Where(a => a.UserId == userId!.Id && a.Token == refreshToken).FirstOrDefault(b => b.IsSignedIn);
            if(checkUserStatus == null || !checkUserStatus.IsSignedIn)
            {
                return new AuthResult()
                {
                    Result = false,
                    Message = "No user logged in currently to log out. First log in to log out from current session !!"
                };
            }
            checkUserStatus!.IsSignedIn = false; // make it false to log out the user
            _appDbContext.SaveChanges();

            return new AuthResult()
            {
                Result = true,
                Message = "User logged out successfully !!"
            };
        }

        public async Task<AuthResult> CheckUserLoggedInStatus(string user)
        {
            var userId = await _userManager.FindByEmailAsync(user);
            var checkUserStatus = _appDbContext.RefreshTokens.Where(a => a.UserId == userId!.Id ).FirstOrDefault(b => b.IsSignedIn);
            if (checkUserStatus == null || !checkUserStatus.IsSignedIn)
            {
                return new AuthResult()
                {
                    Result = false,
                    Message = "No user logged in currently. !!"
                };
            }

            return new AuthResult()
            {
                Result = true,
                Message = "User is logged in !!"
            };
        }
        //string Send2FACode(string username, string password)
        //{
        //    throw new NotImplementedException();
        //}

        //bool Verify2FACode(string username, string password)
        //{
        //    throw new NotImplementedException();
        //}
    }
}
