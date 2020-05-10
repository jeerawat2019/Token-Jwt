using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using AspWebApiJWTModule.Model;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Namespace
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
       private IConfiguration _config;
       public LoginController(IConfiguration config)
       {
           _config = config;
       }
       public IActionResult Login(string username,string pass)
        {
            UserModel login = new UserModel();
            login.UserName = username;
            login.Password = pass;
            IActionResult response = Unauthorized();
            
            var user = AuthenticateUser(login);

            if(user != null)
            {
                var tokenStr = GenerateJSonWebToken(user);
            }
            return response;
        }

        private string GenerateJSonWebToken(UserModel userinfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
            var claims = new []
            {
                new Claim(JwtRegisteredClaimNames.Sub,userinfo.UserName),
                new Claim(JwtRegisteredClaimNames.Email,userinfo.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };
            var Token = new JwtSecurityToken(
                issuer:_config["Jwt:Issuer"],
                audience:_config["Jwt:Issuer"],
                claims,
                expires:DateTime.Now.AddMinutes(120),
                signingCredentials:credentials);
            var encodetoken = new JwtSecurityTokenHandler().WriteToken(Token);
            return encodetoken;
        }
        
        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;
            if(login.UserName =="ashproghelp"&& login.Password =="123")
            {
                user = new UserModel{UserName ="AshProgHelp",EmailAddress = "ashproghelp@gmail.com",Password = "123"};
            }
            return user;
        }
        [Authorize]
        [HttpPost("Post")]
        public string post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();
            var username = claim[0].Value;
            return "Welcom To: "+ username;
        }
        [Authorize]
        [HttpGet("GetValue")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] {"value1","value2","value3"};
        }
    }
}