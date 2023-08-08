using LogWorkService.Services;
using Serilog;

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

#endregion

builder.Services.AddControllers();

var app = builder.Build();

app.UseSerilogRequestLogging();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();