namespace JWTAuth.Models
{
    public class AuthResult
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
        public bool Result { get; set; }

        public string? Message { get; set; }
        public List<string>? Errors { get; set; }
        public List<string>? Roles { get; set; }
    }
}
