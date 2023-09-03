using JWTAuth.Data;
using JWTAuth.Models;
using JWTAuth.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Collections;

namespace JWTAuth.Services
{
    public class TeamsService : ITeamsService
    {
        private readonly AppDbContext _appDbContext;
        private readonly UserManager<IdentityUser> _userManager;
        public TeamsService(AppDbContext appDbContext, UserManager<IdentityUser> userManager)
        {
            _appDbContext = appDbContext;
            _userManager = userManager;
        }

        public async Task<IEnumerable> Get(string userId)
        {
            var check = await CheckUserLoggedInStatus(userId);
            if (check.Result)
            {
                var teams = await _appDbContext.Teams.ToListAsync();
                return teams;
            }
            return "User not logged in !!";
        }

        public async Task<IEnumerable> GetById(string userId, int id)
        {
            var check = await CheckUserLoggedInStatus(userId);
            if (check.Result)
            {
                var team = await _appDbContext.Teams.FirstOrDefaultAsync(a => a.Id == id);
                if (team == null)
                {
                    return null!;
                }
                var res = new List<Team> { team };
                return res;
            }
            return "User not logged in !!";
        }

        public async Task<string> AddTeam(string userId, Team team)
        {
            var check = await CheckUserLoggedInStatus(userId);
            if (check.Result)
            {
                await _appDbContext.Teams.AddAsync(team);
                await _appDbContext.SaveChangesAsync();
                // returning the the created team as result
                return $"Created successfulyy with  id {team.Id}";
            }
            return "User not logged in !!";
        }

        public async Task<IEnumerable> EditTeam(string userId, int id, string country)
        {
            var check = await CheckUserLoggedInStatus(userId);
            if (check.Result)
            {
                var team = await _appDbContext.Teams.FirstOrDefaultAsync(a => a.Id == id);
                if (team == null)
                {
                    return $"Not found with {id} this id";
                }
                team.Country = country;
                await _appDbContext.SaveChangesAsync();

                var res = await GetById(userId, id);

                return res;
            }
            return "User not logged in !!";
        }

        public async Task<IEnumerable> DeleteTeam(string userId, int id)
        {
            var check = await CheckUserLoggedInStatus(userId);
            if (check.Result)
            {
                var team = await _appDbContext.Teams.FirstOrDefaultAsync(a => a.Id == id);
                if (team == null)
                {
                    return $"Not found with {id} this id";
                }
                _appDbContext.Teams.Remove(team);
                await _appDbContext.SaveChangesAsync();

                return $"Team with {id} deleted successfully !!";
            }
            return "User not logged in !!";
        }
        public async Task<AuthResult> CheckUserLoggedInStatus(string user)
        {
            var userId = await _userManager.FindByEmailAsync(user);
            var checkUserStatus = _appDbContext.RefreshTokens.Where(a => a.UserId == userId!.Id).FirstOrDefault(b => b.IsSignedIn);
            if (checkUserStatus == null || !checkUserStatus.IsSignedIn)
            {
                return new AuthResult()
                {
                    Result = false,
                    Message = "No user logged in currently. !!"
                };
            }

            return new AuthResult()
            {
                Result = true,
                Message = "User is logged in !!"
            };
        }
    }
}
