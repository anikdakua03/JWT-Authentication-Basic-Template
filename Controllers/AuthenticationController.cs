using JWTAuth.Data;
using JWTAuth.DTOs;
using JWTAuth.Helper;
using JWTAuth.Models;
using JWTAuth.Services;
using JWTAuth.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthenticationController(IHttpContextAccessor httpContextAccessor, IAuthService authService)
        {
            _httpContextAccessor = httpContextAccessor;
            _authService = authService;
        }

        /// <summary>
        /// First time user registration
        /// </summary>
        /// <param name="userRegistrationRequestDTO"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDTO userRegistrationRequestDTO)
        {
            if (ModelState.IsValid)
            {
                var isCreated = await _authService.UserRegister(userRegistrationRequestDTO);
                // fecthing the errors
                List<string> allErrors = new List<string>();
                int errorCount = isCreated!.Errors!.Count();
                if (errorCount > 0)
                {
                    for (int i = 0; i < errorCount; i++)
                    {
                        var er = isCreated!.Errors!.ToList().ElementAt(i);
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
            if (userId == null || code == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>() { "Invalid email information!!" }
                });
            }
            try
            {
                var res = await _authService.ConfirmUserEmail(userId, code);

                return Ok(res);
                    //.Succeeded ? "Thank you for confirming your email" : "Email confirmation failed, please try again later !");
            }
            catch (Exception)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>() { "Email confirmation failed, please try again later !" }
                });
            }
        }

        /// <summary>
        /// User login and giving user a token 
        /// </summary>
        /// <param name="userLoginRequestDTO"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO userLoginRequest)
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
                // now will create jwt token for this user for this session
                var jwtTokenString = await _authService.UserLogin(userLoginRequest);

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
        /// User login with 2 factor code and giving user a token 
        [HttpPost]
        [Route("LoginWithTwoFA")]
        public async Task<IActionResult> LoginWithTwoFA(string userEmail, string twoFactorCode)
        {
            if (twoFactorCode == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Not in valid format!!"
                    }
                });
            }

            try
            {
                // now will create jwt token for this user for this session
                var jwtTokenString = await _authService.UserLoginWithTwoFA(userEmail, twoFactorCode);

                // then return it and redirection to homepage 
                return Ok(jwtTokenString);
            }
            catch (Exception ex)
            {
                return BadRequest(new AuthResult()
                {
                    Message = ex.Message,
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

            var result = await _authService.VerifyAndGenerateToken(tokenRequest);
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
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return NotFound("Cannot be empty !!");
            }

            try
            {
                var result = await _authService.ForgotPasswordAsync(email);

                return Ok(result);
            }
            catch (Exception)
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
        /// Change the password
        /// </summary>
        /// <param name="resetPasswordDTO"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO resetPasswordDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new AuthResult()
                {
                    Message = " Some invalid parameters !!"
                });
            }

            try
            {
                var result = await _authService.ResetPasswordAsync(resetPasswordDTO);

                return Ok(result);
            }
            catch (Exception)
            {
                return BadRequest(new AuthResult()
                {
                    Message = " Something went wrong !!",
                });
            }
        }

        /// <summary>
        /// For getting current user's session
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("GetSession")]
        public IEnumerable<string> GetSesssionInfo()
        {
            List<string> sessionInfo = new List<string>();

            var currentUserId = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (currentUserId == null)
            {
                sessionInfo.Add("Currently no user logged in !!");
                return sessionInfo;
            }
            HttpContext.Session.SetString(Session.SessionKeyUserName.ToString(), currentUserId!); // add the current user
            HttpContext.Session.SetString(Session.SessionKeySessionId, HttpContext.Session.Id);
            var userName = HttpContext.Session.GetString(Session.SessionKeyUserName);
            var sessionId = HttpContext.Session.GetString(Session.SessionKeySessionId);

            sessionInfo.Add(userName!);
            sessionInfo.Add(sessionId!);

            return sessionInfo;
        }

        /// <summary>
        /// Sign out the user
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("SignOut")]
        public async Task<IActionResult>  Signout(string userId, string refreshToken) // string userId , sesionid
        {
            //var result = await _emailService.SignOutUser();
            HttpContext.Session.Clear();
            foreach (var cookie in Request.Cookies.Keys)
            {
                Response.Cookies.Delete(cookie);
            }

            //return Ok(result);

            // Using custom signout
            var result = await  _authService.CustomSignOutUser(userId, refreshToken);
            return Ok(result);
        }
    }
}
