from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    # App
    app_name: str = "Specter"
    log_level: str = "INFO"
    environment: str = "production"

    # Database
    database_type: Literal["sqlite", "postgres"] = "sqlite"
    sqlite_path: str = "/data/specter.db"
    postgres_dsn: str = ""

    # MCP Server
    mcp_server_url: str = "http://mcp-server.workload.svc.cluster.local:8000/mcp"

    # Threat retention — Specter is a detection broker, not a system of record.
    # Threats older than this are purged; customers ship to their SIEM for long-term storage.
    threat_retention_hours: int = 72
    threat_purge_interval_minutes: int = 15

    # Inventory discovery loop — interrogates the cluster for AI workloads.
    # The discovered inventory is the source of truth for rule scoping.
    inventory_interval_minutes: int = 60

    # Trusted installer allowlist — loaded from a ConfigMap-mounted YAML.
    # Principals matching any of these globs are exempt from mutation-class rules.
    trusted_installers_path: str = "/etc/specter/trusted-installers.yaml"

    # OIDC / SSO
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:9000/auth/callback"
    oidc_scopes: str = "openid profile email"

    # Scanners
    scanner_k8s_enabled: bool = True
    scanner_aws_enabled: bool = False
    scanner_gcp_enabled: bool = False
    scanner_azure_enabled: bool = False
    scanner_ibm_enabled: bool = False
    scanner_alibaba_enabled: bool = False

    # AWS
    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""

    # GCP
    gcp_project_id: str = ""
    gcp_credentials_json: str = ""

    # Azure
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    # IBM
    ibm_api_key: str = ""
    ibm_region: str = "us-south"

    # Alibaba
    alibaba_access_key_id: str = ""
    alibaba_access_key_secret: str = ""
    alibaba_region_id: str = "cn-hangzhou"

    # Observability
    splunk_enabled: bool = False
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    cribl_enabled: bool = False
    cribl_url: str = ""
    grafana_enabled: bool = False
    grafana_url: str = ""
    grafana_api_key: str = ""

    @property
    def database_url(self) -> str:
        if self.database_type == "postgres":
            return self.postgres_dsn
        return f"sqlite+aiosqlite:///{self.sqlite_path}"

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
