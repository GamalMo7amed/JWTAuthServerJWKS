using JWTAuthServer.Data;
using JWTAuthServer.DTOs;
using JWTAuthServer.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTAuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Authentication : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;

        public Authentication(IConfiguration configuration, ApplicationDbContext context)
        {
            _configuration = configuration;
            _context = context;
        }
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var client = _context.Clients
                .FirstOrDefault(c => c.ClientId == loginDto.ClientId);
            if (client == null)
            {
                return Unauthorized("Invalid client credentials.");
            }
            var user = await _context.Users
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role) 
                .FirstOrDefaultAsync(u => u.Email.ToLower() == loginDto.Email.ToLower());
            if (user == null)
            {
                return Unauthorized("Invalid credentials.");
            }
            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password);
            if (!isPasswordValid)
            {
                return Unauthorized("Invalid credentials.");
            }
            var token = GenerateJwtToken(user, client);
            return Ok(new { Token = token });
        }
        private string GenerateJwtToken(User user,Client client)
        {
            var signingKey = _context.SigningKeys.FirstOrDefault(s => s.IsActive);
            if (signingKey == null)
            {
                throw new InvalidOperationException("No active signing key found.");
            }
            var privateKeyBytes = Convert.FromBase64String(signingKey.PrivateKey);
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
            var rsaSecurityKey = new RsaSecurityKey(rsa)
            {
                KeyId = signingKey.KeyId
            };
            var creds = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.Firstname),
                new Claim(ClaimTypes.NameIdentifier, user.Email),
                new Claim(ClaimTypes.Email, user.Email)
            };
            foreach (var userRole in user.UserRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name));
            }
            var tokenDescriptor = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"], // The token issuer, typically your application's URL
                audience: client.ClientURL, // The intended recipient of the token, typically the client's URL
                claims: claims, // The list of claims to include in the token
                expires: DateTime.UtcNow.AddHours(1), // Token expiration time set to 1 hour from now
                signingCredentials: creds // The credentials used to sign the token
            );
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.WriteToken(tokenDescriptor);
            return token;
        }
    }
}
