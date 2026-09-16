using System.Collections.Concurrent;
using Microsoft.AspNetCore.SignalR;
using ThreatDetector.Models;

namespace ThreatDetector.Api.Hubs;

public class ThreatHub : Hub
{
    private static readonly ConcurrentDictionary<string, HashSet<string>> _subscriptions = new();

    public async Task SubscribeToSource(string source)
    {
        var group = $"source:{source}";
        await Groups.AddToGroupAsync(Context.ConnectionId, group);
        _subscriptions.GetOrAdd(group, _ => new HashSet<string>()).Add(Context.ConnectionId);
        await Clients.Caller.SendAsync("Subscribed", source);
    }

    public async Task UnsubscribeFromSource(string source)
    {
        var group = $"source:{source}";
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, group);
        if (_subscriptions.TryGetValue(group, out var subs))
            subs.Remove(Context.ConnectionId);
        await Clients.Caller.SendAsync("Unsubscribed", source);
    }

    public async Task SendThreatAlert(ThreatAlert alert)
    {
        await Clients.All.SendAsync("ThreatAlert", alert);
    }

    public async Task SendConceptUpdate(ConceptUpdate update)
    {
        await Clients.All.SendAsync("ConceptUpdate", update);
    }

    public async Task SendMetrics(DashboardMetrics metrics)
    {
        await Clients.All.SendAsync("Metrics", metrics);
    }

    public override async Task OnConnectedAsync()
    {
        await Clients.Caller.SendAsync("Connected", new { connectionId = Context.ConnectionId });
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        foreach (var group in _subscriptions.Keys)
        {
            if (_subscriptions.TryGetValue(group, out var subs))
                subs.Remove(Context.ConnectionId);
        }
        await base.OnDisconnectedAsync(exception);
    }
}
