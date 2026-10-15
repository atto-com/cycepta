using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Polly;
using System;
using System.Net;
using Microsoft.Extensions.Http.Resilience;

namespace ThreatDetector.Parsing.Feeds.RssFeedParser.RssFeedClient
{
    public class RssClientClass
    {
        public const string HttpClientName = "ClientRssFeed";

        private const string RssUserAgent = "ThreatDetector/1.0 (security research; RSS aggregator)";

        private readonly ILogger<RssClientClass> _logger;

        public RssClientClass(ILogger<RssClientClass> logger)
        {
            _logger = logger;
        }

        public void HttpclientFeedRss(IServiceCollection serviceDescriptors)
        {
            try
            {
                var clienthttp = serviceDescriptors.AddHttpClient(HttpClientName, client =>
                {
                    client.DefaultRequestHeaders.Accept.ParseAdd(
                        "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5");
                    client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
                    client.DefaultRequestHeaders.UserAgent.ParseAdd(RssUserAgent);

                    client.Timeout = Timeout.InfiniteTimeSpan;

                    client.DefaultRequestVersion = HttpVersion.Version20;
                    client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
                });
                //clienthttp.AddPolicyHandler(Policy.TimeoutAsync<HttpResponseMessage>(
                //    TimeSpan.FromSeconds(20),
                //    Polly.Timeout.TimeoutStrategy.Pessimistic,
                //    onTimeoutAsync: async (context, timespan, task) =>
                //    {
                //        _logger.LogWarning("⏰ RSS-запрос истёк после {Timeout}", timespan);
                //        await Task.CompletedTask;
                //    }));
                //clienthttp.AddTransientHttpErrorPolicy(policy => policy.CircuitBreakerAsync(
                //    handledEventsAllowedBeforeBreaking: 10,
                //    durationOfBreak: TimeSpan.FromMinutes(1),
                //    onBreak: (outco, timespan) =>
                //    {
                //        _logger.LogWarning("CircuitBreaker (RSS): circuit opened for {Timespan}", timespan);
                //    },
                //    onHalfOpen: () =>
                //    {
                //        _logger.LogWarning("CircuitBreaker (RSS): half-open");
                //    },
                //    onReset: () =>
                //    {
                //        _logger.LogWarning("CircuitBreaker (RSS): circuit reset");
                //    }));
                clienthttp.AddResilienceHandler("builderRss", build =>
                {
                    build.AddTimeout(new HttpTimeoutStrategyOptions
                    {
                        Timeout = TimeSpan.FromMinutes(5),
                        OnTimeout = args =>
                        {
                            _logger.LogWarning($"⏰ Таймаут: {args.Timeout}");
                            return ValueTask.CompletedTask;
                        }
                    });

                    build.AddRetry(new HttpRetryStrategyOptions
                    {
                        MaxRetryAttempts = 5,
                        BackoffType = DelayBackoffType.Exponential,
                        Delay = TimeSpan.FromSeconds(5),
                        MaxDelay = TimeSpan.FromSeconds(30),
                        UseJitter = true,
                        OnRetry = args =>
                        {
                            _logger.LogWarning($"🔁 Попытка #{args.AttemptNumber} через {args.RetryDelay}. " +
                                                 $"Причина: {args.Outcome.Exception?.Message ?? args.Outcome.Result?.StatusCode.ToString()}");
                            return ValueTask.CompletedTask;
                        }
                    });
                });
                clienthttp.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
                {
                    EnableMultipleHttp2Connections = true,

                    PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
                    PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,

                    UseCookies = false,

                    AllowAutoRedirect = true,
                    MaxAutomaticRedirections = 10,

                    MaxConnectionsPerServer = 5
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to configure RSS client settings");
                throw;
            }
        }
    }
}
