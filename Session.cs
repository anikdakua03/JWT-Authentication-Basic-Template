namespace JWTAuth
{
    public class Session
    {
        public const string SessionKeyUserName = "MySession";
        public const string SessionKeySessionId = "SessionId";
    }

    public enum SessionState 
    {
        SessionKeyUserName = 0,
        SessionKeySessionId = 1
    }
}
