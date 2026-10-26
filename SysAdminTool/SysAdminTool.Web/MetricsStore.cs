namespace SysAdminTool.Web;

/// <summary>
/// المخزن المركزي (في الذاكرة): السيرفرات، القراءات، التنبيهات، وسجل النشاط.
/// كل العمليات thread-safe لأن الـ background services والـ API بيستخدموه في نفس الوقت.
/// لاحقاً تقدر تستبدله بقاعدة بيانات (SQLite) من غير ما تغيّر باقي الكود كتير.
/// </summary>
public class MetricsStore
{
    public const int MaxSamples = 900;          // آخر 900 قراءة لكل سيرفر
    public const int MaxActivity = 500;
    public const double Threshold = 90;          // نسبة الاستهلاك اللي بعدها يتفتح تنبيه
    public static readonly TimeSpan OfflineAfter = TimeSpan.FromSeconds(15);

    private readonly object _lock = new();
    private readonly Dictionary<string, ServerInfo> _servers = new();
    private readonly Dictionary<string, List<Sample>> _samples = new();
    private readonly Dictionary<string, bool> _isUp = new();
    private readonly List<AlertItem> _alerts = new();
    private readonly List<ActivityItem> _activity = new();
    private long _alertId;
    private long _activityId;

    // ---------- الكتابة ----------

    /// <summary>إضافة قراءة قديمة (لملء الرسم عند التشغيل) من غير فحص التنبيهات.</summary>
    public void Seed(ServerInfo info, Sample sample)
    {
        lock (_lock)
        {
            Register(info);
            Append(info.Id, sample);
        }
    }

    /// <summary>إضافة قراءة جديدة وفحص الحدود.</summary>
    public void AddSample(ServerInfo info, Sample sample)
    {
        lock (_lock)
        {
            Register(info);
            Append(info.Id, sample);

            if (!_isUp[info.Id])
            {
                _isUp[info.Id] = true;
                Resolve(info.Id, "Down");
                Log("system", $"Server back online: {_servers[info.Id].Name}", info.Id);
            }

            Evaluate(info.Id, "HighCpu", "CPU", sample.Cpu);
            Evaluate(info.Id, "HighRam", "RAM", sample.Ram);
            Evaluate(info.Id, "HighDisk", "Disk", sample.Disk);
        }
    }

    /// <summary>أي سيرفر سكت أكتر من OfflineAfter يتعلّم Down ويتفتحله تنبيه.</summary>
    public void CheckOffline()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            foreach (var id in _servers.Keys.ToList())
            {
                var list = _samples[id];
                if (list.Count == 0 || !_isUp[id]) continue;

                if (now - list[^1].TimeUtc > OfflineAfter)
                {
                    _isUp[id] = false;
                    Open(id, "Down", "Server stopped reporting");
                }
            }
        }
    }

    // ---------- القراءة (للداشبورد) ----------

    public List<ServerStatus> GetServers()
    {
        lock (_lock)
        {
            return _servers.Values
                .OrderBy(s => s.Name)
                .Select(s =>
                {
                    var list = _samples[s.Id];
                    Sample? last = list.Count > 0 ? list[^1] : null;
                    return new ServerStatus(
                        s.Id, s.Name, s.Host, s.Group,
                        _isUp[s.Id] ? "up" : "down",
                        last, last?.TimeUtc);
                })
                .ToList();
        }
    }

    public List<Sample> GetHistory(string serverId, int minutes)
    {
        lock (_lock)
        {
            if (!_samples.TryGetValue(serverId, out var list)) return new List<Sample>();
            var from = DateTime.UtcNow.AddMinutes(-Math.Clamp(minutes, 1, 30));
            return list.Where(s => s.TimeUtc >= from).ToList();
        }
    }

    public List<AlertItem> GetAlerts(bool onlyActive)
    {
        lock (_lock)
        {
            return _alerts
                .Where(a => !onlyActive || a.ResolvedUtc == null)
                .OrderByDescending(a => a.OpenedUtc)
                .Take(100)
                .ToList();
        }
    }

    public List<ActivityItem> GetActivity(int limit)
    {
        lock (_lock)
        {
            return _activity
                .OrderByDescending(a => a.Id)
                .Take(Math.Clamp(limit, 1, 200))
                .ToList();
        }
    }

    // ---------- داخلي (لازم يتنادى جوه الـ lock) ----------

    private void Register(ServerInfo info)
    {
        if (_servers.ContainsKey(info.Id)) return;

        _servers[info.Id] = info;
        _samples[info.Id] = new List<Sample>();
        _isUp[info.Id] = true;
        Log("system", $"Server registered: {info.Name}", info.Id);
    }

    private void Append(string serverId, Sample sample)
    {
        var list = _samples[serverId];
        list.Add(sample);
        if (list.Count > MaxSamples) list.RemoveAt(0);
    }

    private void Evaluate(string serverId, string type, string label, double value)
    {
        if (value >= Threshold) Open(serverId, type, $"{label} usage at {value:0}%");
        else Resolve(serverId, type);
    }

    private void Open(string serverId, string type, string message)
    {
        if (_alerts.Any(a => a.ServerId == serverId && a.Type == type && a.ResolvedUtc == null)) return;

        var name = _servers[serverId].Name;
        _alerts.Add(new AlertItem(++_alertId, serverId, name, type, message, DateTime.UtcNow, null));
        if (_alerts.Count > 500) _alerts.RemoveAt(0);
        Log("system", $"Alert opened: {name} - {message}", serverId);
    }

    private void Resolve(string serverId, string type)
    {
        var index = _alerts.FindIndex(a => a.ServerId == serverId && a.Type == type && a.ResolvedUtc == null);
        if (index < 0) return;

        var resolved = _alerts[index] with { ResolvedUtc = DateTime.UtcNow };
        _alerts[index] = resolved;
        Log("system", $"Alert resolved: {resolved.ServerName} - {resolved.Message}", serverId);
    }

    private void Log(string actor, string action, string? serverId)
    {
        _activity.Add(new ActivityItem(++_activityId, DateTime.UtcNow, actor, action, serverId));
        if (_activity.Count > MaxActivity) _activity.RemoveAt(0);
    }
}
