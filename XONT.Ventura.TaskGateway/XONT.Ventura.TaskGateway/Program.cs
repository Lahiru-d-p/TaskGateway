using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using XONT.Ventura.TaskGateway;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DAL;
using XONT.Ventura.TaskGateway.DOMAIN;
using Yarp.ReverseProxy;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Your API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Enter 'Bearer' followed by your token in the text box below.\nExample: Bearer abc123",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));


builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(Convert.ToInt32(builder.Configuration["Jwt:ExpireMinutes"]));
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
   {
       options.RequireHttpsMetadata = false;
       options.SaveToken = true;
       options.IncludeErrorDetails = true;
       options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("TaskAccess", policy =>
        policy.RequireAuthenticatedUser().AddRequirements(new TaskAuthorizationRequirement()));
});

builder.Services.AddSingleton<IAuthorizationHandler, TaskAuthorizationHandler>();
builder.Services.AddHttpContextAccessor();


var pluginPath = Path.Combine(AppContext.BaseDirectory, "Plugins");
if (Directory.Exists(pluginPath))
{
    foreach (var dll in Directory.GetFiles(pluginPath, "*.dll"))
    {
        try
        {
            Assembly.LoadFrom(dll);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to load {dll}: {ex.Message}");
        }
    }
}

var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
var assembliesToLoad = new Queue<AssemblyName>();

foreach (var asmName in Assembly.GetExecutingAssembly().GetReferencedAssemblies())
{
    assembliesToLoad.Enqueue(asmName);
}

var matchedAssemblies = new List<Assembly>();

while (assembliesToLoad.Count > 0)
{
    var asmName = assembliesToLoad.Dequeue();

    if (!visited.Add(asmName.FullName))
        continue;

    if (!asmName.Name.StartsWith("XONT.VENTURA", StringComparison.OrdinalIgnoreCase))
        continue;

    try
    {
        var asm = Assembly.Load(asmName);

        if (asmName.Name.Contains("BLL", StringComparison.OrdinalIgnoreCase) ||
            asmName.Name.Contains("DAL", StringComparison.OrdinalIgnoreCase)) 
        {
            matchedAssemblies.Add(asm);
        }

        foreach (var child in asm.GetReferencedAssemblies())
        {
            assembliesToLoad.Enqueue(child);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to load {asmName.Name}: {ex.Message}");
    }
}


foreach (var assembly in matchedAssemblies)
{
    var types = assembly.GetTypes()
        .Where(t => t.IsClass && !t.IsAbstract );

    foreach (var type in types)
    {
        var interfaceType = type.GetInterfaces()
            .FirstOrDefault(i => i.Name == $"I{type.Name}");

        if (interfaceType != null)
        {
            builder.Services.AddScoped(interfaceType, type);
        }
        else
        {
            builder.Services.AddScoped(type);
        }
    }
}

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Your API V1");
    });
}
app.UseSession();
app.UseHttpsRedirection();

app.UseStaticFiles(); 

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapReverseProxy();

app.MapWhen(context => !context.Request.Path.StartsWithSegments("/api"), subApp =>
{
    subApp.UseStaticFiles();
    subApp.Use(async (context, next) =>
    {
        var taskId = context.Request.Path.Value.Split('/')[1];
        if (!string.IsNullOrEmpty(taskId))
        {
            var filePath = Path.Combine(app.Environment.WebRootPath, taskId, "index.html");
            if (File.Exists(filePath))
            {
                context.Response.ContentType = "text/html";
                await context.Response.SendFileAsync(filePath);
                return;
            }
        }
        await next();
    });
});

app.Run();
