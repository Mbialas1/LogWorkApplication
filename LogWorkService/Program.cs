using LogWorkService.Authorization;
using LogWorkService.Authorization.Cache;
using LogWorkService.Services;
using Microsoft.AspNetCore.Authentication;
using Serilog;
using StackExchange.Redis;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.ResponseCompression;

var builder = WebApplication.CreateBuilder(args);

// Configure the HTTP request pipeline.

var configuration = builder.Configuration;
builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .WriteTo.Console());


builder.Services.AddResponseCompression(options =>
{
    options.Providers.Add<GzipCompressionProvider>();
    options.Providers.Add<BrotliCompressionProvider>();
    options.EnableForHttps = true;
});

// Add services to the container.

#region Services

builder.Services.AddScoped<TaskService>();

builder.Services.AddScoped<RedisCacheAuthorizationService>();

builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(builder.Configuration.GetSection("Redis:Configuration").Value));

builder.Services.AddControllers();

builder.Services.AddAuthentication("BasicAuthentication")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);

// AspNetCoreRateLimit
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
builder.Services.AddInMemoryRateLimiting();
#endregion

var app = builder.Build();

app.UseResponseCompression();

app.UseSerilogRequestLogging();

app.UseHttpsRedirection();

app.MapControllers();

app.UseAuthentication();

app.UseAuthorization();

app.UseIpRateLimiting();

app.Run();
