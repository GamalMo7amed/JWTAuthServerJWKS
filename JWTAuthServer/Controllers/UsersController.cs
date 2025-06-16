using JWTAuthServer.Data;
using JWTAuthServer.DTOs;
using JWTAuthServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JWTAuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public UsersController(ApplicationDbContext context)
        {
            _context = context;
        }
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == model.Email.ToLower());
            if (existingUser != null)
            {
                return Conflict(new { message = "Email is already registered." });
            }
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);
            var newUser = new Models.User
            {
                Firstname = model.Firstname,
                Lastname = model.Lastname,
                Email = model.Email,
                Password = hashedPassword
            };
            await _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();
            var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == "user");
            if(userRole!= null)
            {
               var newUserRole = new UserRole
               {
                    UserId = newUser.Id,
                    RoleId = userRole.Id
               };
                await _context.UserRoles.AddAsync(newUserRole);
                await _context.SaveChangesAsync();
            }
            return CreatedAtAction(nameof(GetProfile), new { id = newUser.Id }, new { message = "User registered successfully." });
        }
        [HttpGet("GetProfile")]
        [Authorize]
        public async Task<IActionResult> GetProfile()
        {
            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            if (emailClaim == null)
            {
                return Unauthorized(new { message = "Invalid token: Email claim missing." });
            }
            string userEmail = emailClaim.Value;
            var user = await _context.Users.Include(u=>u.UserRoles)
                                            .ThenInclude(ur => ur.Role)
                                            .FirstOrDefaultAsync(u => u.Email.ToLower() == userEmail.ToLower());
            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }
            var profile = new ProfileDTO
            {
                Id = user.Id,
                Email = user.Email,
                Firstname = user.Firstname,
                Lastname = user.Lastname,
                Roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
            };
            return Ok(profile);
        }
        [HttpPut("UpdateProfile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDTO updateDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            if (emailClaim == null)
            {
                return Unauthorized(new { message = "Invalid token: Email claim missing." });
            }
            string userEmail = emailClaim.Value;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == userEmail.ToLower());
            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }
            if (!string.IsNullOrEmpty(updateDto.Firstname))
            {
                user.Firstname = updateDto.Firstname;
            }
            if (!string.IsNullOrEmpty(updateDto.Lastname))
            {
                user.Lastname = updateDto.Lastname;
            }
            if (!string.IsNullOrEmpty(updateDto.Email) && updateDto.Email != user.Email)
            {
                var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == updateDto.Email.ToLower());
                if (existingUser != null)
                {
                    return Conflict(new { message = "Email is already registered." });
                }
                user.Email = updateDto.Email;
            }
            if (!string.IsNullOrEmpty(updateDto.Password))
            {
                user.Password = BCrypt.Net.BCrypt.HashPassword(updateDto.Password);
            }
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            return Ok(new { message = "Profile updated successfully." });
        }
    }
}
