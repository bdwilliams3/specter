from enum import Enum


class ReportFormat(str, Enum):
    csv = "csv"
    html = "html"
    json = "json"


class ReportEntity(str, Enum):
    assets = "assets"
    threats = "threats"
    vulnerabilities = "vulnerabilities"
