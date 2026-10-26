namespace SysAdminTool.Web;

/// <summary>سيرفر مسجّل في النظام.</summary>
public record ServerInfo(string Id, string Name, string Host, string Group);

/// <summary>قراءة واحدة لاستهلاك الموارد (كلها نسب مئوية ما عدا الشبكة بالـ kbps).</summary>
public record Sample(DateTime TimeUtc, double Cpu, double Ram, double Disk, double NetKbps);

/// <summary>حالة السيرفر الحالية كما تظهر في الداشبورد.</summary>
public record ServerStatus(
    string Id,
    string Name,
    string Host,
    string Group,
    string Status,
    Sample? Latest,
    DateTime? LastSeenUtc);

/// <summary>تنبيه (مفتوح لو ResolvedUtc فاضي).</summary>
public record AlertItem(
    long Id,
    string ServerId,
    string ServerName,
    string Type,
    string Message,
    DateTime OpenedUtc,
    DateTime? ResolvedUtc);

/// <summary>حدث في سجل النشاط.</summary>
public record ActivityItem(long Id, DateTime TimeUtc, string Actor, string Action, string? ServerId);

/// <summary>الشكل اللي الـ agent بيبعته على POST /api/ingest.</summary>
public record IngestDto(
    string ServerId,
    string? Name,
    string? Host,
    string? Group,
    double Cpu,
    double Ram,
    double Disk,
    double NetKbps);
