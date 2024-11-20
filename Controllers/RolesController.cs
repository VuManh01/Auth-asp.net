using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using API.Models;
using API.Dtos;
using Microsoft.EntityFrameworkCore; 
using Microsoft.AspNetCore.Authorization;


namespace API.Controllers
{   
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController:ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;

        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }   

        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if(string.IsNullOrEmpty(createRoleDto.RoleName))
            {
                return BadRequest("Role name is required.");
            }

            var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);

            if(roleExist)
            {
                return BadRequest("Role already exists.");
            }

            var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));

            if(roleResult.Succeeded)
            {
                return Ok(new {message="Role created successfully."});
            }

            return BadRequest("Role creation failed.");
        }
        
        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles() 
        {

            var roles = await _roleManager.Roles.ToListAsync();
            var roleResponses = new List<RoleResponseDto>();

            foreach (var role in roles)
            {   
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
                roleResponses.Add(new RoleResponseDto
            {
                Id = role.Id,
                Name = role.Name,
                TotalUsers = usersInRole.Count
            });
            }

            return Ok(roles);   
        } 
    
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            //  find role by id
            var role = await _roleManager.FindByIdAsync(id);
            if(role == null)
            {
                return NotFound();
            }
            // delete role
            var result = await _roleManager.DeleteAsync(role);
            if(result.Succeeded)
            {
                return Ok(new {message="Role deleted successfully."});
            }
            return BadRequest("Role deletion failed.");
        }

        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await _userManager.FindByIdAsync(roleAssignDto.UserId);

            if(user is null)
            {
                return NotFound("User not found.");
            }

            var role = await _roleManager.FindByIdAsync(roleAssignDto.RoleId);

            if(role is null)
            {
                return NotFound("Role not found.");
            }

            var result = await _userManager.AddToRoleAsync(user, role.Name!);

            if(result.Succeeded)
            {
                return Ok(new {message="Role assigned successfully."});
            }

            var errors = result.Errors.FirstOrDefault();

            return BadRequest(errors.Description);
        }

    }
}