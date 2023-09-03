using JWTAuth.Data;
using JWTAuth.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections;

namespace JWTAuth.Services.Interfaces
{
    public interface ITeamsService
    {
        public Task<IEnumerable> Get(string userId);
        public Task<IEnumerable> GetById(string userId, int id);
        public Task<string> AddTeam(string userId, Team team);
        public Task<IEnumerable> EditTeam(string userId, int id, string country);
        public Task<IEnumerable> DeleteTeam(string userId, int id);
        public Task<AuthResult> CheckUserLoggedInStatus(string user);
    }
}
