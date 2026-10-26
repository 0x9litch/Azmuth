using SysAdminTool.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<MetricsStore>();
builder.Services.AddHostedService<OfflineWatcher>();

// بيانات تجريبية لحد ما الـ agent الحقيقي يجهز
if (builder.Configuration.GetValue("Simulation:Enabled", true))
{
    builder.Services.AddHostedService<SimulationService>();
}

var app = builder.Build();

var apiKey = app.Configuration["Ingest:ApiKey"] ?? "";

app.UseDefaultFiles();   // يفتح wwwroot/index.html تلقائياً
app.UseStaticFiles();

// ---------- API للقراءة (الداشبورد بيستخدمها: مراقبة فقط) ----------

app.MapGet("/api/servers", (MetricsStore store) => store.GetServers());

app.MapGet("/api/servers/{id}/history",
    (string id, int? minutes, MetricsStore store) => store.GetHistory(id, minutes ?? 10));

app.MapGet("/api/alerts",
    (bool? active, MetricsStore store) => store.GetAlerts(active ?? false));

app.MapGet("/api/activity",
    (int? limit, MetricsStore store) => store.GetActivity(limit ?? 50));

// ---------- API الاستقبال (الـ agent بيبعت عليها بياناته) ----------

static double Pct(double v) => Math.Clamp(v, 0, 100);

app.MapPost("/api/ingest", (HttpRequest request, IngestDto dto, MetricsStore store) =>
{
    if (!string.IsNullOrEmpty(apiKey) && request.Headers["X-Api-Key"] != apiKey)
        return Results.Unauthorized();

    if (string.IsNullOrWhiteSpace(dto.ServerId))
        return Results.BadRequest(new { error = "serverId is required" });

    var info = new ServerInfo(
        dto.ServerId,
        dto.Name ?? dto.ServerId,
        dto.Host ?? "",
        dto.Group ?? "default");

    store.AddSample(info, new Sample(
        DateTime.UtcNow, Pct(dto.Cpu), Pct(dto.Ram), Pct(dto.Disk), Math.Max(0, dto.NetKbps)));

    return Results.Ok();
});

app.Run();
