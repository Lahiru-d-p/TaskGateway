using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XONT.Ventura.TaskGateway.DOMAIN
{

    public class UserLogin
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
    public class UserLoginResponse
    {
        public string Token { get; set; }
        public string Message { get; set; }
    }

}
