using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;
using XONT.Ventura.TaskGateway.BLL;


namespace XONT.Ventura.TaskGateway;
public class TaskAuthorizationRequirement : IAuthorizationRequirement { }

public class TaskAuthorizationHandler : AuthorizationHandler<TaskAuthorizationRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, TaskAuthorizationRequirement requirement)
    {

        if (context.Resource is HttpContext httpContext)
        {
            var taskid = httpContext.Request.RouteValues["taskid"]?.ToString();
            var controller = httpContext.Request.RouteValues["controller"]?.ToString();
            string? task = (taskid ?? controller)?.Trim();

            if (string.IsNullOrWhiteSpace(task))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            List<string> unAuthTaskList = httpContext.Session.GetObject<List<string>>("UnAuthorizedTasks") ?? new List<string>();


            if (!unAuthTaskList.Any())
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }
            else if (unAuthTaskList.Contains(task, StringComparer.OrdinalIgnoreCase))
            {
                context.Fail();
                return Task.CompletedTask;
            }
            else
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }
        }
        else
        {
            context.Fail();
            return Task.CompletedTask;
        }


    }
}
