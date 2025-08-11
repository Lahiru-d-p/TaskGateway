using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using XONT.Ventura.TaskGateway;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DAL;
using XONT.Ventura.TaskGateway.DOMAIN;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
        options.SerializerSettings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto;
    });
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Task Gateway API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Enter 'Bearer' followed by your token\nExample: Bearer abc123",
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
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped< AuthDAL>();
builder.Services.AddScoped<DBHelper>();
builder.Services.AddHttpContextAccessor();

var pluginPath = Path.Combine("E:/LahiruDilshan", "TaskDlls");
var loadedAssemblies = new List<Assembly>();

if (Directory.Exists(pluginPath))
{

    foreach (var dllPath in Directory.GetFiles(pluginPath, "*.dll"))
    {
        try
        {
            var assemblyName = AssemblyLoadContext.GetAssemblyName(dllPath);
            var assembly = Assembly.LoadFrom(dllPath);
            loadedAssemblies.Add(assembly);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to load {dllPath}: {ex.Message}");
        }
    }
}
else
{
    Console.WriteLine($"Plugin folder not found: {pluginPath}. No plugins loaded.");
}
foreach (var assembly in loadedAssemblies)
{
    var assemblyName = assembly.GetName().Name;

    if (assemblyName.EndsWith(".Web", StringComparison.OrdinalIgnoreCase))
    {
        builder.Services.AddControllers().AddApplicationPart(assembly);
        continue;
    }
    if (!assemblyName.EndsWith(".BLL", StringComparison.OrdinalIgnoreCase) &&
        !assemblyName.EndsWith(".DAL", StringComparison.OrdinalIgnoreCase))
    {
        continue;
    }

    var types = assembly.GetTypes()
        .Where(t => t.IsClass &&
                    !t.IsAbstract &&
                    !t.IsInterface)
        .ToList();

    foreach (var type in types)
    {
        if (type.Name.StartsWith("<") || string.IsNullOrEmpty(type.Name)) continue;

        var serviceInterface = type.GetInterface($"I{type.Name}");

        if (serviceInterface != null)
        {
            builder.Services.AddScoped(serviceInterface, type);
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
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Task Gateway API V1");
    });
}

app.UseSession();
app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();