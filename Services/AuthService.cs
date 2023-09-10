using JWTAuth.Data;
using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using JWTAuth.Services.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Services
{
    public class AuthService : IAuthService
    {
        private readonly IEmailService _emailService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _appDbContext;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthService(IEmailService emailService, UserManager<IdentityUser> userManager, AppDbContext appDbContext, TokenValidationParameters tokenValidationParameters, IConfiguration configuration, SignInManager<IdentityUser> signInManager, IHttpContextAccessor httpContextAccessor)
        {
            _emailService = emailService;
            _userManager = userManager;
            _appDbContext = appDbContext;
            _tokenValidationParameters = tokenValidationParameters;
            _configuration = configuration;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<AuthResult> UserRegister(UserRegistrationRequestDTO userRegistrationRequestDTO)
        {
            // not checking role , bcs default it will be user

            // check email already exists or not
            var existed_user = await _userManager.FindByEmailAsync(userRegistrationRequestDTO.Email!); // adding! because this will prevent any null value

            if (existed_user != null) // means email exists
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email already exists !!"
                    }
                };
            }

            // create user
            var newUser = new IdentityUser()
            {
                Email = userRegistrationRequestDTO.Email,
                UserName = userRegistrationRequestDTO.Name,
                // forcing email not to be verified
                EmailConfirmed = false
            };

            var isCreated = await _userManager.CreateAsync(newUser, userRegistrationRequestDTO.Password!);

            if (isCreated.Succeeded)
            {
                // assign role as default User
                await _userManager.AddToRoleAsync(newUser, "User");
                // this generates unique email confirmation code
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

                var emailSend = await _emailService.SendMailAsync(newUser, WebUtility.UrlEncode(code));

                if (emailSend.Result! != false) // need
                {
                    return new AuthResult()
                    {
                        Result = true,
                        Token = "",
                        RefreshToken = "",
                        Message = "Please verify your email , just sent to you."
                    };
                }
            }
            return new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Something went wrong , please check again !!"
                }
            };
        }

        public async Task<AuthResult> UserLogin(UserLoginRequestDTO userLoginRequest)
        {
            // check if user exists or not
            var userExists = await _userManager.FindByEmailAsync(userLoginRequest.Email!);
            if (userExists == null)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Please register yourself first !!"
                    }
                };
            }

            // check if anyone already logged in or not
            // but for first time user logged in , it cannot found that in refresh table 
            //var checkUserStatus = await CheckUserLoggedInStatus(userExists.Email!);
            //if (checkUserStatus == true)
            //{
            //    return new AuthResult()
            //    {
            //        Result = false,
            //        Errors = new List<string>()
            //        {
            //            "Hey !! already logged in some where , please log out first and try again loggin in !!"
            //        }
            //    };
            //}

            // now will check the user s email is confirmed or not
            if (!userExists.EmailConfirmed)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email not yet confirmed !!"
                    }
                };
            }

            var isCorrectPassword = _userManager.CheckPasswordAsync(userExists!, userLoginRequest.Password!);
            // now will check the user s password
            if (!isCorrectPassword.Result)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Please put your correct password !!"
                    }
                };
            }

            // now will check the 2FA is enabled then send 2FA code via mail
            if (userExists.TwoFactorEnabled)
            {
                //
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(userExists, userLoginRequest.Password!, false, true);

                var code = await _userManager.GenerateTwoFactorTokenAsync(userExists, "Email");

                var res = await _emailService.Send2FAMailAsync(userExists, code);

                return res;
            }

            // for normal user without two factor enabled
            // now will create jwt token for this user for this session
            var jwtTokenString = await GenerateJWTToken(userExists!);

            // then return it and redirection to homepage 
            return jwtTokenString;
        }

        // for user with 2 factor enabled 
        public async Task<AuthResult> UserLoginWithTwoFA(string userEmail, string twoFACode)
        {
            // check if user exists or not
            var userExists = await _userManager.FindByEmailAsync(userEmail);
            if (userExists == null)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Please register yourself first !!"
                    }
                };
            }
            // validate the two factor code
            var validateCodeForUser = await _signInManager.TwoFactorSignInAsync("Email",twoFACode, false, false);
            
            if(validateCodeForUser.Succeeded)
            {
                var jwtTokenString = await GenerateJWTToken(userExists!);
                // then return it and redirection to homepage 
                return jwtTokenString;
            }

            return new AuthResult()
            {
                Result = false,
                Message = "Please request for two factor code first and then try again !!"
            };
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

        public async Task<AuthResult> ConfirmUserEmail(string userId, string code)
        {
            // Do something if token is expired, else continue with confirmation
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid email parameters !!"
                    }
                };
            }

            // verify from user manager
            var res = await _userManager.ConfirmEmailAsync(user, code);

            return new AuthResult()
            {
                Result = res.Succeeded,
                Message = "Thank you for confirming your email !!"
            };
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
                Message = "Logged in successfully!!",
                Roles = new List<string>(dbUserRole)
            };
            return result;
        }

        // forgot password
        public async Task<AuthResult> ForgotPasswordAsync(string email)
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
            var baseUrl = _configuration.GetSection("AppSettings:APIURL").Value;
            var resetLink = $"{baseUrl}Authentication/ResetPassword?Email={email}&token={newToken}";
            // send to the user
            MailRequest resetMailRequest = new MailRequest()
            {
                ToMail = email,
                Subject = "Reset your password !",
                Body = GetResetPasswordHtmlBody(resetLink)
            };
            await _emailService.SendMailAsync(existed_user, newToken);

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
                };
            }
            // check with existed current password
            var existed_user_old_pass = await _userManager.CheckPasswordAsync(existed_user, resetPasswordDTO.OldPassword!); // adding! because this will prevent any null value

            if (!existed_user_old_pass) // means invalid
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Please put your current password first !!"
                    }
                }; 
            }

            var result = await _userManager.ResetPasswordAsync(existed_user!, resetPasswordDTO.Token!, resetPasswordDTO.NewPassword!);

            if (!result.Succeeded)
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
            await _emailService.SendMailAsync(existed_user, resetPasswordDTO.Token!);
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

        public async Task<AuthResult> CustomSignOutUser(string user, string refreshToken)
        {
            // if isSignedin false means user not logged in
            var userId = await _userManager.FindByEmailAsync(user);
            var checkUserStatus = _appDbContext.RefreshTokens.Where(a => a.UserId == userId!.Id && a.Token == refreshToken).FirstOrDefault(b => b.IsSignedIn);
            if (checkUserStatus == null || !checkUserStatus.IsSignedIn)
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

        public async Task<bool> CheckUserLoggedInStatus(string user)
        {
            //var checking = _httpContextAccessor.HttpContext!.User.Identity!.IsAuthenticated;
            var userId = await _userManager.FindByEmailAsync(user);
            var checkUserStatus = await _appDbContext.RefreshTokens.Where(a => a.UserId == userId!.Id).FirstOrDefaultAsync();

            return checkUserStatus!.IsSignedIn; // for first time login need to check
        }

        // this will convert seconds to a foramttable year:month:day:hour:minutes:seconds:miliseconds
        public DateTime UtcTimeStampToDateTime(long utcExpiryDate)
        {
            var dateTimeValue = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeValue = dateTimeValue.AddSeconds(utcExpiryDate).ToLocalTime();
            return dateTimeValue;
        }

        public string RandomStringGenerate(int len)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_";

            var myString = new string(Enumerable.Repeat(chars, len).Select(a => a[random.Next(a.Length)]).ToArray());

            return myString;
        }

        public string GetResetPasswordHtmlBody(string link)
        {
            string emailBody = "<h1> Reset your password </h1>";
            emailBody += $"Please use the link to reset !!<a href=\"{link}\"> <strong>Click here</strong> </a>";
            emailBody += "<div style=\"width:100%;background-color:lightblue;text-align:center;margin:10px\">";
            emailBody += "</div>";
            return emailBody;
        }

    }
}
