# SysAdmin Monitor — الـ Backend والداشبورد (.NET)

داشبورد مراقبة (للقراءة فقط) لمشروع Linux System Administration Tool.
فيه بيانات سيرفرات تجريبية شغالة لوحدها، لحد ما الـ agent الحقيقي يجهز.

## التشغيل (3 خطوات)

1. فك ضغط الملف في أي مكان (مثلاً سطح المكتب).
2. دوس مرتين على **SysAdminTool.sln** عشان يفتح في Visual Studio.
3. اضغط **F5**. المتصفح هيفتح على `http://localhost:5080`.

المفروض تشوف:
- 4 سيرفرات تجريبية بنسب الاستهلاك (بتتحدث كل 3 ثواني)
- رسوم CPU / RAM / Disk / Network للسيرفر اللي اخترته (دوس على أي كارت سيرفر)
- بعد حوالي دقيقة: تنبيه CPU عالي على `db-01`
- بعد حوالي دقيقتين: `staging-01` يقع (offline) ويرجع، وتنبيه يتفتح ويتقفل
- بعد حوالي 7 دقايق: تنبيه Disk على `backup-01`
- سجل النشاط بيسجل كل ده

## لو حصلت مشكلة

| المشكلة | الحل |
|---|---|
| خطأ `NETSDK1045` أو "does not support targeting .NET 10.0" | افتح `SysAdminTool.Web.csproj` وغيّر `net10.0` لرقم النسخة اللي عندك (مثلاً `net8.0`) |
| خطأ إن البورت 5080 مشغول | افتح `Properties/launchSettings.json` وغيّر `5080` لرقم تاني |
| صفحة فاضية أو 404 | اتأكد إن الملف `wwwroot/index.html` موجود جوه مجلد المشروع |

لو ظهر أي خطأ تاني، انسخ نصه كامل وابعتهولي.

## الملفات

| الملف | وظيفته |
|---|---|
| `Program.cs` | تعريف الـ API (القراءة + استقبال بيانات الـ agent) |
| `MetricsStore.cs` | تخزين القراءات والتنبيهات وسجل النشاط (في الذاكرة) |
| `SimulationService.cs` | توليد بيانات تجريبية + فحص السيرفرات اللي سكتت |
| `Models.cs` | شكل البيانات |
| `wwwroot/index.html` | صفحة الداشبورد |
| `appsettings.json` | الإعدادات (تشغيل المحاكاة، مفتاح الـ API) |

## الـ API

للداشبورد (قراءة فقط):

- `GET /api/servers` — السيرفرات وحالتها وآخر قراءة
- `GET /api/servers/{id}/history?minutes=10` — قراءات آخر دقايق
- `GET /api/alerts` — التنبيهات (`?active=true` للمفتوحة بس)
- `GET /api/activity?limit=50` — سجل النشاط

## ربط الـ agent الحقيقي (للزميل اللي ماسك الـ TUI/agent)

الـ agent يبعت قراءة كل كام ثانية على:

```
POST /api/ingest
X-Api-Key: dev-key-123
Content-Type: application/json

{ "serverId": "web-01", "name": "Web Server 01", "host": "10.0.0.11",
  "group": "production", "cpu": 23.5, "ram": 61.2, "disk": 48.0, "netKbps": 1200 }
```

- `cpu` و`ram` و`disk` نسب مئوية من 0 لـ 100، و`netKbps` سرعة الشبكة.
- السيرفر بيتسجل تلقائياً أول مرة يبعت.
- لو سكت أكتر من 15 ثانية، بيتعلّم offline ويتفتحله تنبيه.
- لما الـ agent يجهز، اقفل البيانات التجريبية: في `appsettings.json` خلّي `"Simulation": { "Enabled": false }`.
- غيّر قيمة `Ingest:ApiKey` في `appsettings.json` قبل أي تسليم أو عرض.

## فتح الداشبورد من جهاز تاني

الـ backend على Linux والداشبورد تفتحها من Windows: شغّل التطبيق على `http://0.0.0.0:5080` (بدل localhost) وافتح من المتصفح `http://<IP السيرفر>:5080`.
ولو فيه firewall على السيرفر افتح البورت (`sudo ufw allow 5080/tcp`).

## الخطوات الجاية

1. حفظ القراءات في SQLite (عشان البيانات متضيعش لما التطبيق يتقفل).
2. عرض الـ processes لكل سيرفر (زي Task Manager).
3. إرسال التنبيهات على Telegram أو Email.
4. تسجيل دخول للداشبورد (authentication).
