using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Serilog;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using XONT.Ventura.TaskGateway;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DAL;
using XONT.Ventura.TaskGateway.DOMAIN;
using XONT.Ventura.TaskGateway.Infrastructure;
using XONT.Ventura.TaskGateway.Middlewares;

var builder = WebApplication.CreateBuilder(args);

#region Configure Logging
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .CreateLogger();

builder.Host.UseSerilog();
#endregion

#region Configure Controllers and JSON
builder.Services.AddControllers()
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
        options.SerializerSettings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto;
    });

#endregion

#region Configure CORS
var appConsoleOrigin = builder.Configuration["AppConsoleOrigin"] ??"";

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAppConsole", policy =>
    {
        policy.WithOrigins(appConsoleOrigin)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});
#endregion

#region Configure Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Task Gateway API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Enter Bearer token",
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
#endregion

#region Configure session
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(Convert.ToInt32(builder.Configuration["Jwt:AccessTokenExpirationMinutes"]));
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
#endregion

#region Register services
builder.Services.AddSingleton<IAuthorizationHandler, TaskAuthorizationHandler>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<AuthDAL>();
builder.Services.AddScoped<DBHelper>();
builder.Services.AddHttpContextAccessor();
#endregion

#region Load Plugin Assemblies
try
{
    var pluginPath = Path.Combine(AppContext.BaseDirectory, "TaskDlls");
    PluginLoader.LoadAssembliesAndRegisterServices(builder.Services, pluginPath);
}
catch (Exception ex)
{
    Log.Logger.Error(ex, "Failed to load plugin assemblies.");
}
#endregion

#region Configure authentication & Authorization
var jwtSettings = builder.Configuration.GetRequiredSection("Jwt").Get<JwtSettings>();

builder.Services.Configure<JwtSettings>(builder.Configuration.GetRequiredSection("Jwt"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddScheme<JwtBearerOptions, JwtWithSessionAuthenticationHandler>(
        JwtBearerDefaults.AuthenticationScheme, options =>
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
                ValidIssuer = jwtSettings.Issuer,
                ValidAudience = jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key))
            };
        });


builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("TaskAccess", policy =>
        policy.RequireAuthenticatedUser().AddRequirements(new TaskAuthorizationRequirement()));
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
                               .RequireAuthenticatedUser()
                               .AddRequirements(new TaskAuthorizationRequirement())
                               .Build();
});
#endregion

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Task Gateway API V1");
    });
}

app.UseMiddleware<GlobalExceptionHandlingMiddleware>();
app.UseHttpsRedirection();
app.UseCors("AllowAppConsole");
app.UseRouting();

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapFallback(() =>
    Results.Json(new { Message = "Endpoint not found." }, statusCode: 404));

app.Run();