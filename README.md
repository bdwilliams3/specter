# Specter

**AI Security Posture Management (AISPM)** for Kubernetes and multi-cloud environments.

Specter ingests Kubernetes audit logs and eBPF network events, evaluates them against
broad threat detection rules, and surfaces findings to a web UI. Customers ship findings
to their own SIEM; Specter does not retain detections long-term.

---

## Core thesis

Specter is a **detection broker, not a system of record.**

- We ingest, analyze, and surface threats
- The customer owns remediation and long-term storage (SIEM, ticketing)
- Threats are purged from our DB after **72 hours** — predictable, flat-cost
- We don't charge customers ever-increasing fees to store their event data

---

## Architecture

```
                  Customer Cluster                          Specter Control Plane
   ┌──────────────────────────────────────────┐           ┌──────────────────────────┐
   │                                          │           │                          │
   │  kube-apiserver ─audit webhook─┐         │           │  /api/collector/k8s/     │
   │                                ▼         │           │     ├── audit            │
   │  Tetragon (eBPF) ─tcp_connect─►┐         │           │     └── network          │
   │                                ▼         │           │                          │
   │            specter-collector ──┴─────────┼──HTTPS───►│  Threat detection engine │
   │                                          │           │     ├── audit_rules      │
   │  ghost-agent ──┐                         │           │     └── network_rules    │
   │  mcp-server  ──┴── (AI workloads)        │           │                          │
   │                                          │           │  threat_events (SQLite)  │
   └──────────────────────────────────────────┘           │     ├── 72h hard TTL     │
                                                          │     └── purge every 15m  │
                                                          │                          │
                                                          │  React UI + WebSocket    │
                                                          │  REST API → SIEM ship    │
                                                          └──────────────────────────┘
```

---

## Components

| Component               | Path                       | Role                                                    |
|-------------------------|----------------------------|---------------------------------------------------------|
| FastAPI backend         | `app/`                     | REST API, threat detection, persistence, WebSocket      |
| React frontend          | `frontend/`                | Threats, assets, posture dashboards                     |
| Helm chart              | `helm/`                    | Kubernetes deployment manifests                         |
| Detection rules         | `app/detectors/`           | Broad audit-event rules (pod exec, RBAC, secrets, ...)  |
| Network rules           | `app/services/network_service.py` | Tetragon-derived AI lateral movement / egress    |
| Retention purge         | `app/services/threat_retention.py` | 72h hard TTL background loop                    |
| Specter collector       | (separate repo: `ghost-server/collector/`) | In-cluster agent: audit + Tetragon → Specter |

---

## Threat schema

Every threat is stored with broad, stable rule names plus structured principal/action
context. Rules describe a class of behavior (`Unexpected Pod Execution over Kubernetes API`),
not a specific instance — the structured fields carry the scoping detail.

```json
{
  "event_id": "4f824a67-7ea5-4538-a2bb-5325cd85003b",
  "threat_name": "Unexpected Pod Execution over Kubernetes API",
  "principal_role": "Kubernetes-Admin",
  "principal_subject": "mcp-server-78c5d7f69b-hzfjc",
  "method": "get",
  "resource": "pods/exec",
  "namespace": "workload",
  "source_ips": ["172.18.0.1"],
  "severity": "critical",
  "category": "unauthorized_access",
  "mitre_atlas": "AML.T0011",
  "detected_at": "2026-04-16T20:47:13.577181Z"
}
```

### Built-in rules (audit)

| Rule                                          | Trigger                                        | MITRE ATLAS  |
|-----------------------------------------------|------------------------------------------------|--------------|
| Unexpected Pod Execution over Kubernetes API  | `pods/exec` or `pods/attach`                   | AML.T0011    |
| Unauthorized AI Secret Access                 | `get`/`list` on `secrets`                      | AML.T0037    |
| Unauthorized RBAC Modification                | mutation on `(cluster)roles`/`(cluster)rolebindings` | AML.T0006 |
| Unsanctioned Pod Creation in AI Namespace     | bare pod (no ownerRef) created in AI ns        | AML.T0007    |
| Service Account Token Harvesting              | `tokenreviews` / `serviceaccounts/token` in AI ns | AML.T0021 |

### Built-in rules (network / Tetragon)

| Rule                                          | Trigger                                        | MITRE ATLAS  |
|-----------------------------------------------|------------------------------------------------|--------------|
| AI Agent Lateral Movement via Internal API    | AI-namespace pod → AI service port (8000, 8080, 11434, ...) | AML.T0011 |
| Unauthorized AI Workload External Egress      | AI-namespace pod → external IP on 443/80       | AML.T0037    |

System actors (`system:kube-*`, `system:node:*`, etc.), loopback connections, and
infra pods (`kube-*`, `coredns-*`, `tetragon-*`, ...) are filtered out as false positives.

---

## Data lifecycle

Specter owns no long-term storage. The `threat_events` table is purged on a hard 72h TTL.

- **TTL:** 72 hours (`THREAT_RETENTION_HOURS`)
- **Purge cadence:** every 15 minutes (`THREAT_PURGE_INTERVAL_MINUTES`)
- **No soft delete, no recovery.** L1 analysts have a 72h window to query the API for automation/triage; after that, data lives only in the customer's SIEM.

---

## API

Base path: `/api`. JWT-authenticated except where noted.

| Endpoint                       | Purpose                                                 |
|--------------------------------|---------------------------------------------------------|
| `GET  /api/threats`            | Paginated threat list (filter: `severity`, `category`)  |
| `GET  /api/threats/{event_id}` | Single threat detail                                    |
| `GET  /api/assets`             | AI asset inventory                                      |
| `GET  /api/graph`              | Asset relationship graph                                |
| `POST /api/scans/trigger`      | Trigger a posture scan                                  |
| `GET  /api/metrics`            | Aggregated counts for dashboards                        |
| `WS   /ws/events`              | Live threat stream                                      |
| `POST /api/collector/k8s/audit`   | Collector → Specter (audit batches)                  |
| `POST /api/collector/k8s/network` | Collector → Specter (Tetragon network events)        |
| `GET  /api/docs`               | OpenAPI / Swagger UI                                    |

---

## Local development

Specter targets a [KIND](https://kind.sigs.k8s.io/) cluster for local dev.

```bash
# Build the image
docker build -t specter:latest .

# Load it into the kind cluster
kind load docker-image specter:latest --name ghost-cluster

# Install / upgrade via Helm
helm upgrade --install specter ./helm -n specter --create-namespace

# Roll out a code change
docker build -t specter:latest . \
  && kind load docker-image specter:latest --name ghost-cluster \
  && kubectl rollout restart deployment/specter -n specter
```

The collector, audit webhook config, and Tetragon manifests live in the separate
`ghost-server/` repo. See its README for cluster bootstrap.

### Frontend dev

```bash
cd frontend
npm install
npm run dev    # vite dev server, proxies /api to specter
```

---

## Configuration

Key env vars (full list in `app/config.py`):

| Variable                          | Default                       | Purpose                                  |
|-----------------------------------|-------------------------------|------------------------------------------|
| `DATABASE_TYPE`                   | `sqlite`                      | `sqlite` or `postgres`                   |
| `SQLITE_PATH`                     | `/data/specter.db`            | SQLite DB path (PVC-mounted in k8s)      |
| `THREAT_RETENTION_HOURS`          | `72`                          | Hard TTL for threats                     |
| `THREAT_PURGE_INTERVAL_MINUTES`   | `15`                          | How often the purge loop runs            |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID`  | (empty)                       | Enables OIDC SSO when both set           |
| `SCANNER_K8S_ENABLED`             | `true`                        | K8s posture scanner                      |
| `SCANNER_AWS_ENABLED`             | `false`                       | AWS scanner (off until phase 2)          |
| `SCANNER_GCP_ENABLED`             | `false`                       | GCP scanner (off until phase 2)          |
| `SCANNER_AZURE_ENABLED`           | `false`                       | Azure scanner (off until phase 2)        |

---

## Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy (async), Pydantic v2
- **Frontend:** React, TypeScript, TanStack Table, Tailwind, Vite
- **Datastore:** SQLite (dev), Postgres (prod-ready)
- **Detection:** rule-based (Python), evaluated per audit/network event
- **eBPF:** Tetragon (deployed separately, gRPC stream consumed by collector)
- **Deploy:** Helm + Kubernetes (KIND for dev, customer clusters for prod)

---

## Roadmap

| Phase | Status        | Scope                                                    |
|-------|---------------|----------------------------------------------------------|
| 1     | In progress   | OIDC/SSO, RBAC, audit + Tetragon ingestion, base rules   |
| 2     | Next          | SIEM connectors: Splunk, Cribl, Grafana, Gravwell        |
| 3     | Planned       | Custom rules/policies (UI + API), rulesets, standards    |
| 4     | Planned       | Multi-cloud scanners (AWS, GCP, Azure)                   |
| 5     | Planned       | CI/CD: GitHub Actions + Argo CD, canary rollouts         |

See `CLAUDE.md` at the repo root for the full strategic plan.

---

## Non-goals

- **System of record** — we ingest and ship; we don't store
- **Compliance reporting** — we flag misconfigurations; customers write reports
- **Automated remediation** — we surface threats; humans/their automation fix them
- **Multi-region replication** — single control plane (for now)
