using Serilog;
using ThreatDetector.Api.Hubs;
using ThreatDetector.Api.Services;
using ThreatDetector.Parsing.Channels;
using ThreatDetector.Parsing.Feeds;
using ThreatDetector.Parsing.Feeds.CveFeedParser;
using ThreatDetector.Parsing.Feeds.CveFeedParser.CveFeedClient;
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
builder.Services.AddHttpClient();
builder.Services.AddHttpClient<RssFeedParser>(client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "ThreatDetector/1.0 (security research)");
});

// NVD CVE feed named client ("ClientCveFeed") with Polly policies
using (var loggerFactory = LoggerFactory.Create(logging => logging.AddSerilog(Log.Logger)))
{
    new ClientClass(loggerFactory.CreateLogger<ClientClass>()).HttpclientFeedCve(builder.Services);
}

// Channel
builder.Services.AddSingleton<DataIngestionChannel>(sp =>
{
    var logger = sp.GetRequiredService<ILogger<DataIngestionChannel>>();
    return new DataIngestionChannel(logger, batchSize: 100, batchWindow: TimeSpan.FromMinutes(5));
});

// NCD HTTP client
builder.Services.AddSingleton<NcdHttpClient>(sp =>
{
    var ncdUrl = builder.Configuration["NcdService:Url"] ?? "http://localhost:5000";
    var logger = sp.GetRequiredService<ILogger<NcdHttpClient>>();
    return new NcdHttpClient(ncdUrl, logger);
});

// Persistence + real-time push
builder.Services.AddSingleton<ThreatStorage>();
builder.Services.AddSingleton<ConceptPersistenceService>();

// Background services
builder.Services.AddHostedService<BatchingService>();

// CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
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

// Feed ingestion endpoint
app.MapPost("/api/v1/ingest", async (
    HttpContext context,
    DataIngestionChannel channel) =>
{
    var documents = await context.Request.ReadFromJsonAsync<List<ThreatDetector.Models.ParsedDocument>>();
    if (documents == null) return Results.BadRequest();

    foreach (var doc in documents)
    {
        await channel.Writer.WriteAsync(doc);
    }

    return Results.Ok(new { accepted = documents.Count });
});

Log.Information("Threat Detector API starting on http://localhost:5001");
app.Run("http://0.0.0.0:5001");
