using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Polly;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ThreatDetector.Parsing.Feeds.CveFeedParser.CveFeedClient
{
   public class ClientClass
    {
        private readonly ILogger<ClientClass> _logger;

        public ClientClass(ILogger<ClientClass> logger)
        {
            _logger = logger;
        }

        public void HttpclientFeedCve(IServiceCollection serviceDescriptors)
        {
            try
            {
                var clienthttp = serviceDescriptors.AddHttpClient("ClientCveFeed", client =>
                {
                    client.DefaultRequestHeaders.AcceptEncoding.ParseAdd("zip, deflate, br");
                    client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

                    client.BaseAddress = new Uri("https://services.nvd.nist.gov/rest/json/cves/2.0");

                    client.DefaultRequestVersion = HttpVersion.Version20;
                    client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
                });
                clienthttp.AddPolicyHandler(Policy.TimeoutAsync<HttpResponseMessage>(
                    TimeSpan.FromMinutes(1),
                    Polly.Timeout.TimeoutStrategy.Pessimistic,
                    onTimeoutAsync: async (context, timespan, task) =>
                    {
                        _logger.LogWarning($"⏰ Request timed out after {timespan} from Client_1" + DateTime.UtcNow);
                        await Task.CompletedTask;
                    }));
                clienthttp.AddTransientHttpErrorPolicy(policy => policy.CircuitBreakerAsync(
                    handledEventsAllowedBeforeBreaking: 5,
                    durationOfBreak: TimeSpan.FromMinutes(1),
                    onBreak: (outco,timespan) =>
                    {
                        _logger.LogWarning($"Cистема CircuitBreaker: circuit opened for {timespan}");
                    },
                    onHalfOpen: () =>
                    {
                        _logger.LogWarning("Cистема CircuitBreaker: half-open");
                    },
                    onReset: ()=>
                    {
                        _logger.LogWarning("Cистема CircuitBreaker: circuit reset");
                    }));
                clienthttp.AddTransientHttpErrorPolicy(polly => polly.WaitAndRetryAsync(3, retrycount =>
                TimeSpan.FromSeconds(Math.Pow(2, retrycount)) +
                TimeSpan.FromMilliseconds(Random.Shared.Next(0, 100)),
                onRetryAsync: (outcome, timespan, retrycount, task) =>
                {
                    _logger.LogWarning($"Повтор запроса #{retrycount} через {timespan}");
                    return Task.CompletedTask;
                }));
                clienthttp.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler()
                {
                    EnableMultipleHttp2Connections = true,

                    PooledConnectionIdleTimeout = TimeSpan.FromMinutes(10),
                    PooledConnectionLifetime = TimeSpan.FromMinutes(20),

                    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,

                    UseCookies = false,

                    AllowAutoRedirect = true,
                    MaxAutomaticRedirections = 10,

                    MaxConnectionsPerServer = 5

                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to Client Settings" + ex.StackTrace);
                throw;
            }
        }
    }
}
