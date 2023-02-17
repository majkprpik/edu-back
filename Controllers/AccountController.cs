using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using edu_back.DTOs;
using edu_back.Entities;
using edu_back.JWT;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace edu_back.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly User testUser;
    private readonly JwtHandler _jwtHandler;
    protected readonly IConfiguration Configuration;

    public AccountController(JwtHandler jwtHandler, IConfiguration configuration)
    {
        testUser = new User() { Id = 1, UserName = "test", Password = "test123" };
        _jwtHandler = jwtHandler;
        Configuration = configuration;
    }

    [HttpPost]
    [Route("login-jwt")]
    public async Task<IActionResult> LoginJWT([FromBody] UserForLoginDTO userForAuthentication)
    {
        var success = await Task.Run(() => userForAuthentication.UserName == testUser.UserName && userForAuthentication.Password == testUser.Password);

        if (!success)
            return Unauthorized();

        var claimsData = new[]
           {
                new Claim("id", testUser.Id.ToString()),
                new Claim("userName", testUser.UserName),
           };

        var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetValue<string>("JWT:Secret")));
        var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
        var tokenOptions = new JwtSecurityToken(
            issuer: Configuration.GetValue<string>("JWT:ValidIssuer"),
            audience: Configuration.GetValue<string>("JWT:ValidAudience"),
            claims: claimsData,
            expires: DateTime.Now.AddMinutes(25),
            signingCredentials: signinCredentials
        );
        var accessToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

        tokenOptions = new JwtSecurityToken(
            issuer: Configuration.GetValue<string>("JWT:ValidIssuer"),
            audience: Configuration.GetValue<string>("JWT:ValidAudience"),
            claims: claimsData,
            signingCredentials: signinCredentials
        );
        var refreshToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

        return Ok(new JWTTokenResponse { AccessToken = accessToken, RefreshToken = refreshToken });
    }

    [HttpPost]
    [Route("login-basic")]
    public async Task<IActionResult> LoginBasic([FromBody] UserForLoginDTO userForAuthentication)
    {
        var success = await Task.Run(() => userForAuthentication.UserName == testUser.UserName && userForAuthentication.Password == testUser.Password);

        if (!success)
            return Unauthorized();

        return Ok("Success");
    }
}