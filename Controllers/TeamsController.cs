using JWTAuth.Data;
using JWTAuth.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Controllers
{
    // authorized by particularly JWTAthuentication bearer
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class TeamsController : ControllerBase
    {
        private readonly AppDbContext _context;
        public TeamsController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var teams = await _context.Teams.ToListAsync();
            return Ok(teams);
        }
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(a => a.Id == id);
            if (team == null)
            {
                return BadRequest($"Not found with {id} this id");
            }
            return Ok(team);
        }
        
        [HttpPost]
        public async Task<IActionResult> AddTeam(Team team)
        {
            await _context.Teams.AddAsync(team);
            await _context.SaveChangesAsync();
            // returning the the created team as result
            return CreatedAtAction("Get", team.Id, team);
        }
        
        [HttpPatch]
        public async Task<IActionResult> EditTeam(int id, string country)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(a => a.Id == id);
            if (team == null)
            {
                return BadRequest($"Not found with {id} this id");
            }
            team.Country = country;
            await _context.SaveChangesAsync();
            // returning the the created team as result
            return NoContent();
        }
        [HttpDelete]
        public async Task<IActionResult> DeleteTeam(int id)
        {
            try
            {
                var team = await _context.Teams.FirstOrDefaultAsync(a => a.Id == id);
                            if (team == null)
                            {
                                return BadRequest($"Not found with {id} this id");
                            }
                            _context.Teams.Remove(team);
                            await _context.SaveChangesAsync();
                            // returning the the created team as result
                            return NoContent();
            }
            catch (Exception)
            {

                throw;
            } 
        }
    }
}
