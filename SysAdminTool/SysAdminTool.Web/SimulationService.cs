namespace SysAdminTool.Web;

/// <summary>
/// بيولّد بيانات سيرفرات تجريبية كل ثانيتين، لحد ما الـ agent الحقيقي يجهز.
/// بيحاكي: ارتفاع CPU (db-01)، سيرفر بيقع (staging-01)، وهارد بيمتلي (backup-01).
/// عطّله من appsettings.json: "Simulation": { "Enabled": false }
/// </summary>
public class SimulationService : BackgroundService
{
    private record Sim(string Id, string Name, string Host, string Group,
        double Cpu, double Ram, double Disk, double DiskRate, double Phase);

    private static readonly Sim[] Servers =
    {
        new("web-01", "Web Server 01", "10.0.0.11", "production", 35, 55, 48, 0.0005, 0.0),
        new("db-01", "Database 01", "10.0.0.12", "production", 40, 68, 71, 0.001, 1.3),
        new("staging-01", "Staging 01", "10.0.0.21", "staging", 20, 40, 35, 0.0005, 2.1),
        new("backup-01", "Backup 01", "10.0.0.31", "backup", 12, 30, 86, 0.01, 3.4),
    };

    private readonly MetricsStore _store;

    public SimulationService(MetricsStore store) => _store = store;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var start = DateTime.UtcNow;

        // ملء آخر 5 دقايق عشان الرسوم تبان فوراً
        for (var back = -300; back < 0; back += 2)
        {
            var time = start.AddSeconds(back);
            foreach (var s in Servers)
            {
                var sample = Generate(s, back, time);
                if (sample != null) _store.Seed(ToInfo(s), sample);
            }
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - start).TotalSeconds;

            foreach (var s in Servers)
            {
                var sample = Generate(s, elapsed, now);
                if (sample != null) _store.AddSample(ToInfo(s), sample);
            }

            try { await Task.Delay(2000, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private static Sample? Generate(Sim s, double t, DateTime time)
    {
        // staging-01 بيقع من الثانية 100 لـ 145 في كل دورة 180 ثانية
        if (s.Id == "staging-01" && Mod(t, 180) >= 100 && Mod(t, 180) < 145) return null;

        var cpu = s.Cpu + 12 * Math.Sin(t / 25 + s.Phase) + Noise(4);

        // db-01: CPU عالي من الثانية 60 لـ 85 في كل دورة 120 ثانية
        if (s.Id == "db-01" && Mod(t, 120) >= 60 && Mod(t, 120) < 85) cpu = 94 + Noise(3);

        var ram = s.Ram + 4 * Math.Sin(t / 60 + s.Phase) + Noise(1);
        var disk = s.Disk + s.DiskRate * t;
        var net = 300 + Math.Max(cpu, 1) * 40 * (0.5 + Random.Shared.NextDouble());

        return new Sample(time, Clamp(cpu), Clamp(ram), Clamp(disk), Math.Round(net));
    }

    private static double Mod(double t, double m) => ((t % m) + m) % m;

    private static double Noise(double amplitude) => (Random.Shared.NextDouble() * 2 - 1) * amplitude;

    private static double Clamp(double v) => Math.Round(Math.Clamp(v, 0, 100), 1);

    private static ServerInfo ToInfo(Sim s) => new(s.Id, s.Name, s.Host, s.Group);
}

/// <summary>بيفحص كل 5 ثواني: هل فيه سيرفر سكت ومبعتش بيانات؟</summary>
public class OfflineWatcher : BackgroundService
{
    private readonly MetricsStore _store;

    public OfflineWatcher(MetricsStore store) => _store = store;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _store.CheckOffline();

            try { await Task.Delay(5000, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
}
