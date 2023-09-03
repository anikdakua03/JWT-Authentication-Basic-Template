using JWTAuth.Data;
using JWTAuth.Models;
using JWTAuth.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class TeamsController : ControllerBase
    {
        private readonly ITeamsService _teamsService;
        public TeamsController(ITeamsService teamsService)
        {
            _teamsService = teamsService;
        }

        //[Authorize(Roles = "Admin")]
        [HttpGet]
        [Route("GetAllTeams")]
        public async Task<IActionResult> Get(string userId)
        {
            var teams = await _teamsService.Get(userId);
            if(teams != null)
            {
                return Ok(teams);
            }
            return BadRequest("User not logged in !!");
        }

        [HttpGet]
        [Route("GetTeamById")]
        public async Task<IActionResult> GetById(string userId, int id)
        {
            var team = await _teamsService.GetById(userId,id);

            if (team == null)
            {
                return BadRequest($"Not found with {id} this id");
            }
            return Ok(team);
        }

        //[Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("AddTeam")]
        public async Task<IActionResult> AddTeam(string userId, Team team)
        {
            var res = await _teamsService.AddTeam(userId, team);

            return Ok(res);
        }

        //[Authorize(Roles = "Admin")]
        [HttpPatch]
        [Route("EditTeam")]
        public async Task<IActionResult> EditTeam(string userId, int id, string country)
        {
            var team = await _teamsService.EditTeam(userId, id, country);
            if (team == null)
            {
                return BadRequest(team);
            }
            return Ok(team);
        }

        //[Authorize(Roles = "Management")]
        [HttpDelete]
        [Route("DeleteTeam")]
        public async Task<IActionResult> DeleteTeam(string userId, int id)
        {
            var team = await _teamsService.DeleteTeam(userId, id);
            if (team == null)
            {
                return BadRequest(team);
            }
            return Ok(team);
        }
    }
}
