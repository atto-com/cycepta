using Serilog;
using ThreatDetector.Api.Hubs;
using ThreatDetector.Api.Services;
using ThreatDetector.Parsing.Feeds;
using ThreatDetector.Storage;

var builder = WebApplication.CreateBuilder(args);

// Serilog
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .Enrich.FromLogContext()
    .CreateLogger();

builder.Host.UseSerilog();

// Services
builder.Services.AddControllers();
builder.Services.AddSignalR();
builder.Services.AddEndpointsApiExplorer();

// HTTP clients with User-Agent
builder.Services.AddHttpClient<RssFeedParser>(client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "ThreatDetector/1.0 (security research)");
}).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
{
    // RssFeedParser validates each redirect target itself; the default handler
    // would follow a public -> private bounce without giving us a look.
    AllowAutoRedirect = false,
});
builder.Services.AddHttpClient<CveFeedParser>(client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "ThreatDetector/1.0 (security research)");
});

// Persistence + real-time push
builder.Services.AddSingleton<ThreatStorage>();
builder.Services.AddSingleton<ConceptPersistenceService>();

// CORS: the dashboard is same-origin, so only explicitly configured local
// tooling origins are allowed. "*" + credentials is never a safe default.
var allowedOrigins = (builder.Configuration["Cors:AllowedOrigins"]
        ?? "http://localhost:5001,http://127.0.0.1:5001")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
if (allowedOrigins.Length == 0)
{
    allowedOrigins = new[] { "http://localhost:5001", "http://127.0.0.1:5001" };
}
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Middleware
app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();
app.MapHub<ThreatHub>("/hubs/threat");

// Health endpoint
app.MapGet("/health", () => Results.Ok(new { status = "ok", timestamp = DateTime.UtcNow }));

Log.Information("Threat Detector API starting");
app.Run();
