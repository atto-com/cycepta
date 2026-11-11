using Microsoft.AspNetCore.SignalR;

namespace ThreatDetector.Api.Hubs;

/// <summary>
/// Server-to-dashboard push channel. Broadcasts are sent through
/// <see cref="IHubContext{THub}"/> from ConceptPersistenceService; there are
/// deliberately no client-callable methods, otherwise any connected browser
/// could spoof ConceptUpdate/ThreatAlert payloads for every other client.
/// </summary>
public class ThreatHub : Hub
{
    public override async Task OnConnectedAsync()
    {
        await Clients.Caller.SendAsync("Connected", new { connectionId = Context.ConnectionId });
        await base.OnConnectedAsync();
    }
}
