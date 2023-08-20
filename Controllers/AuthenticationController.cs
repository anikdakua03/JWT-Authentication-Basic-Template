using JWTAuth.Configurations;
using JWTAuth.Data;
using JWTAuth.DTOs;
using JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using RestSharp.Authenticators;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        // private readonly JWTConfig _jwtConfig;
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _appDbContext;
        private readonly TokenValidationParameters _tokenValidationParameters;
        public AuthenticationController(UserManager<IdentityUser> userManager, IConfiguration configuration, AppDbContext
             appDbContext, TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            // _jwtConfig = jwtConfig;
            _configuration = configuration;
            _appDbContext = appDbContext;
            _tokenValidationParameters = tokenValidationParameters;
        }

        /// <summary>
        /// First Time user registration
        /// </summary>
        /// <param name="userRegistrationRequestDTO"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDTO userRegistrationRequestDTO)
        {
            // validate the incmoing request from frontend
            if(ModelState.IsValid)
            {
                // check email already exists or not
                var existed_user = await _userManager.FindByEmailAsync(userRegistrationRequestDTO.Email!); // adding! because this will prevent any null value


                if(existed_user != null) // means email exists
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Email already exists !!"
                        }
                    }); // or we can also create custom exceptions 
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

                if(isCreated.Succeeded)
                {
                    // create token for this from GenerateJWTToken
                    // var tokenString = GenerateJWTToken(newUser);
                    // return Ok(new AuthResult()
                    //{
                    //    Result = true,
                    //    Token = tokenString
                    //});

                    // this generates unique email confirmation code
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

                    var emailBody = "Please confirm your email <a href=\"#URL#\"> Click Here </a>";

                    // eg. : https://localhost:5121/authentication/verifyemail/user/userID=SOME_ID&code=THTA_CODE
                    var callbackURL = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", "Authentication", new {userId = newUser.Id, code});
                    // now encoding the email body bcs in code , there may be # ^ escape char , which may affect the url
                    var body = emailBody.Replace("#URL#", System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callbackURL));

                    // sent this email from that email client
                    var emailSend = SendEmail(body, newUser.Email!);

                    if(emailSend)
                    {
                        return Ok("Please verify your email , just sent to you.");
                    }
                    return Ok("Please request again for your email verification link !!");
                }
                // fecthing the errors
                List<string> allErrors = new List<string>();
                int errorCount = isCreated.Errors.Count();
                if(errorCount > 0)
                {
                    for (int i = 0; i < errorCount; i++)
                    {
                        var er = isCreated.Errors.ToList().ElementAt(i).Description.ToString();
                        allErrors.Add(er);
                    }
                }
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = allErrors
                }) ; // or we can also create custom exceptions
            }

            return BadRequest();
        }

        /// <summary>
        /// Email validation
        /// </summary>
        /// <param name="userLoginRequest"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if(userId == null || code == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid email information!!"
                    }
                });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid email parameters !!"
                    }
                });
            }
            // decode the code
            code = Encoding.UTF8.GetString(Convert.FromBase64String(code));
            var res = await _userManager.ConfirmEmailAsync(user, code);
            
            return Ok(res.Succeeded ? "Thank you for confirming your email" : "Email confirmation failed, please try again later !");
        }

        /// <summary>
        /// User login and giving user a token 
        /// </summary>
        /// <param name="userLoginRequestDTO"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody]UserLoginRequestDTO userLoginRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Not a valid format for email / password!!"
                    }
                });
            }

            try
            {
                // check if user exists or not
                var userExists = await _userManager.FindByEmailAsync(userLoginRequest.Email!);
                if (userExists == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid payload !!"
                        },
                    });
                }
                // now will check the user s email is confirmed or not
                if(!userExists.EmailConfirmed)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Email not yet confirmed !!"
                        },
                    });
                }

                var isCorrectPassword =  _userManager.CheckPasswordAsync(userExists!, userLoginRequest.Password!);

                // now will create jwttoken for this user for this session
                var jwtTokenString = await GenerateJWTToken(userExists!);

                // then return it and redirection to homepage 
                return Ok(jwtTokenString);
            }
            catch (Exception)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Doesn't exists or invalid credentials !!"
                    },
                    Result = false
                });
            }
        }

        /// <summary>
        /// Refreshing user token
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "In valid parameters!!"
                    }
                });
            }

            var result = await VerifyAndGenerateToken(tokenRequest);
            if (result == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid tokens!!"
                    }
                });
            }
            return Ok(result);
        }

        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenhandler = new JwtSecurityTokenHandler();

            try
            {
                _tokenValidationParameters.ValidateLifetime = false; // for local dev only

                var tokenInVerification = jwtTokenhandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                // different types of validation with different rules
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    // will validate againsted the actual jwt token tokens creation algorithms
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (!result) return null; // invalid or not matching
                }

                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(a => a.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UtcTimeStampToDateTime(utcExpiryDate); 

                if(DateTime.UtcNow  > expiryDate) // means crossed the expiry date , so  invalid token
                {
                    return  new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid token !!"
                        }
                    };
                }
                // now compared with stored token in db
                var storedToken = await _appDbContext.RefreshTokens.FirstOrDefaultAsync(a => a.Token == tokenRequest.RefreshToken);
                if(storedToken == null)
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
                //
                if(storedToken.IsUsed)
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
                //
                if(storedToken.IsRevoked)
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
                //
                var jwtTokenId = tokenInVerification.Claims.FirstOrDefault(a => a.Type == JwtRegisteredClaimNames.Exp).Value;
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
                //
                if (DateTime.UtcNow > storedToken.ExpiryDate)
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
                // now after all validation can create new refresh token also if it is in used by the user
                storedToken.IsUsed = true;
                _appDbContext.RefreshTokens.Update(storedToken);
                await _appDbContext.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId!);
                var tokenCreation =  await GenerateJWTToken(dbUser);

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

        // this will convert seconds to a foramttable year:month:day:hour:minutes:seconds:miliseconds
        private DateTime UtcTimeStampToDateTime(long utcExpiryDate)
        {
            var dateTimeValue  = new DateTime(1970,1,1,0,0,0,0,DateTimeKind.Utc);
            dateTimeValue = dateTimeValue.AddSeconds(utcExpiryDate).ToUniversalTime();
            return dateTimeValue;
        }

        private async Task<AuthResult> GenerateJWTToken(IdentityUser user)
        {
            var jwtTokenhandler = new JwtSecurityTokenHandler();

            // get that secret encoded in array of bytes
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value!);

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
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
                }),

                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value!)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var newToken = jwtTokenhandler.CreateToken(tokenDescriptor);
            var newJWTToken = jwtTokenhandler.WriteToken(newToken); // this serializes a JWT Security token into a JWT int compact serialization format

            //
            var refreshToken = new RefreshToken()
                {
                    UserId = user.Id,
                    JWTId = newToken.Id,
                    Token = RandomStringGenerate(25), // have to attach refresh token
                    IsUsed = false,
                    IsRevoked = false,
                    AddedDate = DateTime.UtcNow,
                    ExpiryDate = DateTime.UtcNow.AddMonths(1)
                };
            // now save this refresh token to refresh token database
            if(refreshToken != null) await _appDbContext.RefreshTokens.AddAsync(refreshToken);
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
            await _appDbContext.SaveChangesAsync();

            var result = new AuthResult()
            {
                Result = true,
                RefreshToken = refreshToken.Token, // attaching also the refresh token 
                Token = newJWTToken
            };
            return result;
        }

        // We can also create seperate Email service to do the job for sending email
        private bool SendEmail(string body, string email)
        {
            // create email client
            RestClient client = new RestClient("https://api.mailgun.net/v3"); // not using this
            var request = new RestRequest("", Method.Post);

            //client.Authenticator = new HttpBasicAuthenticator("api",_configuration.GetSection("EmailConfig:API_KEY").Value!); // not working so , have to use as an Obsolete options
            var options = new RestClientOptions();
            options.Authenticator = new HttpBasicAuthenticator("api", _configuration.GetSection("EmailConfig:API_KEY").Value!);

            request.AddParameter("domain", "YOUR_DOMAIN_NAME", ParameterType.UrlSegment);

            request.Resource = "{domain}/messages";

            request.AddParameter("from", "Excited User <mailgun@YOUR_DOMAIN_NAME>");

            request.AddParameter("to", email);

            request.AddParameter("subject", "Reconfirm your email");

            request.AddParameter("text", body);

            request.Method = Method.Post; // throw to user

            var response = client.Execute(request);

            return response.IsSuccessful;
        }

        // will help creating random refresh toekn as per our logic
        private string RandomStringGenerate(int len)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_";

            var myString = new string(Enumerable.Repeat(chars, len).Select(a => a[random.Next(a.Length)]).ToArray());

            return myString;
        }
    }
}
