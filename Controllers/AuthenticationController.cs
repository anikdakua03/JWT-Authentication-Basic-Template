using JWTAuth.Data;
using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using JWTAuth.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        
        private readonly IEmailService _emailService;
        public AuthenticationController(UserManager<IdentityUser> userManager, IEmailService emailService)
        {
            _userManager = userManager;
            _emailService = emailService;
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
                    // this generates unique email confirmation code
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                    var  subject = "Test mail from my one of the project ";
                    
                    var emailBody = _emailService.GetHtmlBody();

                    // eg. : https://localhost:5121/authentication/verifyemail/user/userID=SOME_ID&code=THTA_CODE
                    var callbackURL = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", "Authentication", new {userId = newUser.Id, code});

                    // now encoding the email body bcs in code , there may be # ^ escape char , which may affect the url
                    var replacedBody = emailBody.Replace("#URL#",callbackURL);

                    // sent this email from that email client
                    MailRequest mailRequest = new MailRequest()
                    {
                        ToMail = newUser.Email,
                        Subject = subject,
                        Body = replacedBody
                    };

                    var emailSend = await _emailService.SendMailAsync(mailRequest);

                    if(emailSend != null)
                    {
                        return Ok("Please verify your email , just sent to you.");
                    }
                    //return Ok("Please request again for your email verification link !!");
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
                }); // or we can also create custom exceptions
            }

            return BadRequest(new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Some parameters doesn't match our creating new user , please try again !!"
                }
            });
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
            // verify from user manager
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
                var jwtTokenString = await _emailService.GenerateJWTToken(userExists!);

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

            var result = await _emailService.VerifyAndGenerateToken(tokenRequest);
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

        /// <summary>
        /// For email reset link and getting back reset token
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("ForgetPassword")]
        public async Task<IActionResult> ForgotPassword([Required]string email)
        {
            if(string.IsNullOrEmpty(email))
            {
                return NotFound("Cannot be emapty !!");
            }

            try
            {
                var callBackUrl = Request.Scheme + "://" + Request.Host;

                var result = await _emailService.ForgotPasswordAsync(email, callBackUrl);

                return Ok(result);
            }
            catch(Exception)
            {
                return BadRequest(
                    new AuthResult()
                    {
                        Errors = new List<string>()
                    {
                        "Unable to sent !!"
                    }
                    });

            }
        }

        /// <summary>
        /// Chnage the password
        /// </summary>
        /// <param name="resetPasswordDTO"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO resetPasswordDTO)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(new AuthResult()
                {
                    Message = " Some invalid parameters !!"
                });
            }

            try
            {
                var result = await _emailService.ResetPasswordAsync(resetPasswordDTO);

                return Ok(result);
            }
            catch(Exception)
            {
                return BadRequest(new AuthResult()
                {
                    Message = " Something went wrong !!",
                });
            }
        }
    }
}
