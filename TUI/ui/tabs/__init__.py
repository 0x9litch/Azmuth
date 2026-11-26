"""One module per tab. TAB_CLASSES defines their order (F1..F8 / 1..8)."""

from .activity import ActivityTab
from .base import CANCELLED, BaseTab
from .dashboard import DashboardTab
from .files import FilesTab
from .incidents import IncidentDetail, IncidentsTab
from .logs import LogsTab
from .processes import ProcessesTab
from .services import ServicesTab
from .terminal import TerminalTab

TAB_CLASSES = [
    DashboardTab,   # 1
    ServicesTab,    # 2
    ProcessesTab,   # 3
    TerminalTab,    # 4
    FilesTab,       # 5
    LogsTab,        # 6
    IncidentsTab,   # 7
    ActivityTab,    # 8
]

__all__ = [
    "ActivityTab", "BaseTab", "CANCELLED", "DashboardTab", "FilesTab", "IncidentDetail",
    "IncidentsTab", "LogsTab", "ProcessesTab", "ServicesTab", "TAB_CLASSES", "TerminalTab",
]
