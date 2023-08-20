namespace JWTAuth.Configurations
{
    public class JWTConfig
    {
        public string? Secret { get; set; }
        public TimeSpan? ExpiryTimeFrame { get; set; }
    }
}
