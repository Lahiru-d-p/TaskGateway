using XONT.Ventura.AppConsole;

namespace XONT.Ventura.TaskGateway.DOMAIN
{
    public class UserContext
    {
        public User User { get; set; }
        public List<string> UnAuthTasks { get; set; } = new List<string>();
        public string SessionId { get; set; } = string.Empty;
        public BusinessUnit Businessunit { get; set; }
        public string Theme { get; set; } = string.Empty;
        public int Language { get; set; }
        
}
}
