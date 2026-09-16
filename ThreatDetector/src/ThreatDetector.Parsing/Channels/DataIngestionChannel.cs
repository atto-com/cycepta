using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using ThreatDetector.Models;

namespace ThreatDetector.Parsing.Channels;

public class DataIngestionChannel
{
    private readonly Channel<ParsedDocument> _ingestionChannel;
    private readonly Channel<List<ParsedDocument>> _batchChannel;
    private readonly ILogger<DataIngestionChannel> _logger;
    private readonly int _batchSize;
    private readonly TimeSpan _batchWindow;

    public DataIngestionChannel(
        ILogger<DataIngestionChannel> logger,
        int batchSize = 100,
        TimeSpan? batchWindow = null)
    {
        _logger = logger;
        _batchSize = batchSize;
        _batchWindow = batchWindow ?? TimeSpan.FromMinutes(5);

        var ingestionOptions = new BoundedChannelOptions(10000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        };
        _ingestionChannel = Channel.CreateBounded<ParsedDocument>(ingestionOptions);

        var batchOptions = new BoundedChannelOptions(100)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true,
        };
        _batchChannel = Channel.CreateBounded<List<ParsedDocument>>(batchOptions);
    }

    public ChannelWriter<ParsedDocument> Writer => _ingestionChannel.Writer;
    public ChannelReader<List<ParsedDocument>> BatchReader => _batchChannel.Reader;

    public async Task StartBatchingAsync(CancellationToken ct)
    {
        _logger.LogInformation("Batching service started (batchSize={BatchSize}, window={Window}s)",
            _batchSize, _batchWindow.TotalSeconds);

        var batch = new List<ParsedDocument>();
        var timer = DateTime.UtcNow;

        await foreach (var doc in _ingestionChannel.Reader.ReadAllAsync(ct))
        {
            batch.Add(doc);

            var shouldFlush = batch.Count >= _batchSize
                              || (DateTime.UtcNow - timer) >= _batchWindow;

            if (shouldFlush && batch.Count > 0)
            {
                _logger.LogDebug("Flushing batch of {Count} documents", batch.Count);
                await _batchChannel.Writer.WriteAsync(batch, ct);
                batch = new List<ParsedDocument>();
                timer = DateTime.UtcNow;
            }
        }

        if (batch.Count > 0)
        {
            await _batchChannel.Writer.WriteAsync(batch, ct);
        }

        _batchChannel.Writer.Complete();
    }
}
