using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using XONT.Ventura.TaskGateway;
using XONT.Ventura.TaskGateway.BLL;
using XONT.Ventura.TaskGateway.DAL;
using XONT.Ventura.TaskGateway.DOMAIN;
using Yarp.ReverseProxy;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));


builder.Services.AddDistributedMemoryCache(); // Or AddStackExchangeRedisCache for production
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(Convert.ToInt32(builder.Configuration["Jwt:ExpireMinutes"]));
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true; // Required for GDPR if you don't use consent
});
// Configure JWT Authentication
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
builder.Services.AddScoped<DBHelper>();
builder.Services.AddScoped<AuthDAL>();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseStaticFiles(); // To serve Angular files

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapReverseProxy();

// Endpoint to serve the Angular app
app.MapFallbackToFile("/tasks/{taskid}/{*path}", "index.html");

app.Run();
