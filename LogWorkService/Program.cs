using LogWorkService.Authorization;
using LogWorkService.Authorization.Cache;
using LogWorkService.Services;
using Microsoft.AspNetCore.Authentication;
using Serilog;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// Configure the HTTP request pipeline.

var configuration = builder.Configuration;
builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .WriteTo.Console());

// Add services to the container.

#region Services

builder.Services.AddScoped<TaskService>();

builder.Services.AddScoped<RedisCacheAuthorizationService>();

builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(builder.Configuration.GetSection("Redis:Configuration").Value));

builder.Services.AddControllers();

builder.Services.AddAuthentication("BasicAuthentication")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);

#endregion

var app = builder.Build();

app.UseSerilogRequestLogging();

app.UseHttpsRedirection();

app.MapControllers();

app.UseAuthentication();

app.UseAuthorization();

app.Run();