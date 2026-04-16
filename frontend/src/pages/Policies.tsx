import { useState } from 'react'
import { X } from 'lucide-react'
import SeverityBadge from '../components/shared/SeverityBadge'

interface Policy {
  id: string
  title: string
  description: string
  severity: string
  category: string
  cvss_score: number
  remediation: string
  asset_types: string[]
  source: string
}

const POLICIES: Policy[] = [
  {
    id: 'privileged_container',
    title: 'AI workload running in privileged mode',
    description: 'A privileged container has full access to the host. An LLM-driven workload in privileged mode can be exploited via prompt injection to escape the container.',
    severity: 'critical',
    category: 'insecure_config',
    cvss_score: 9.8,
    remediation: 'Remove privileged: true. Drop all capabilities and add only those required.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'no_resource_limits',
    title: 'AI workload has no resource limits',
    description: 'AI workloads without CPU/memory limits can be prompted to run expensive inference loops, exhausting cluster resources and causing denial of service.',
    severity: 'medium',
    category: 'insecure_config',
    cvss_score: 5.0,
    remediation: 'Set CPU and memory requests and limits on all AI containers.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'writable_root_filesystem',
    title: 'AI workload has a writable root filesystem',
    description: 'A writable root filesystem allows an attacker or a compromised LLM agent to write malicious files, install tools, or persist backdoors inside the container.',
    severity: 'medium',
    category: 'insecure_config',
    cvss_score: 5.5,
    remediation: 'Set securityContext.readOnlyRootFilesystem: true. Mount writable volumes only where explicitly needed.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'runs_as_root',
    title: 'AI workload may run as root',
    description: 'Running as root inside the container increases the blast radius of a container escape. An LLM agent compromised via prompt injection could leverage root access for further exploitation.',
    severity: 'medium',
    category: 'insecure_config',
    cvss_score: 5.3,
    remediation: 'Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'automount_sa_token',
    title: 'AI workload auto-mounts Kubernetes API token',
    description: 'The Kubernetes service account token is automatically mounted into this AI workload. A prompt injection attack could instruct the agent to read and exfiltrate this token, granting the attacker cluster API access.',
    severity: 'high',
    category: 'insecure_config',
    cvss_score: 7.5,
    remediation: 'Set automountServiceAccountToken: false in the pod spec unless the workload explicitly needs cluster API access.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'over_permissioned_sa',
    title: 'AI workload has over-permissioned service account',
    description: 'The service account grants dangerous permissions (create/delete/patch/update) on sensitive resources (pods/exec, pods, secrets, clusterroles). An LLM agent with these permissions can be manipulated via prompt injection to execute arbitrary commands, delete workloads, or read secrets.',
    severity: 'critical',
    category: 'over_permissioned',
    cvss_score: 9.1,
    remediation: 'Apply least privilege. Create a dedicated service account for each workload with only the minimum permissions required. Remove exec, delete, and write permissions unless explicitly necessary.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'llm_key_in_env',
    title: 'LLM API credentials exposed via environment variables',
    description: 'LLM API keys are injected as plain environment variables. Environment variables are visible in kubectl describe output, process listings, and crash dumps, increasing the risk of credential exposure.',
    severity: 'medium',
    category: 'insecure_config',
    cvss_score: 6.5,
    remediation: 'Mount credentials from a Secret as a file at a restricted path rather than as environment variables. Restrict access to the Secret with RBAC.',
    asset_types: ['agentic_framework'],
    source: 'k8s',
  },
  {
    id: 'mcp_unauthenticated',
    title: 'MCP server exposes tool execution without authentication',
    description: 'The MCP server accepts tool calls (including write operations like exec and delete) from any caller without authentication. Any workload in the cluster or on the host network can invoke privileged tools.',
    severity: 'critical',
    category: 'missing_auth',
    cvss_score: 9.3,
    remediation: 'Implement authentication on the MCP endpoint (mutual TLS or token-based). Restrict network access to known clients via NetworkPolicy.',
    asset_types: ['mcp_server'],
    source: 'k8s',
  },
  {
    id: 'shared_sa',
    title: 'Service account shared across multiple AI workloads',
    description: 'Sharing a service account violates least privilege — compromising any one workload grants the attacker the permissions of all others sharing the account.',
    severity: 'high',
    category: 'over_permissioned',
    cvss_score: 8.0,
    remediation: 'Create a dedicated service account for each AI workload with only the permissions it requires.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'no_network_policy',
    title: 'AI workloads have no network isolation',
    description: 'The namespace contains AI workloads but has no NetworkPolicy. Any pod in the cluster can reach these AI services, enabling data exfiltration or prompt injection via lateral movement.',
    severity: 'high',
    category: 'no_network_policy',
    cvss_score: 7.5,
    remediation: 'Apply a default-deny NetworkPolicy for each AI namespace and explicitly allow only required ingress/egress.',
    asset_types: ['mcp_server', 'agentic_framework', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'nodeport_exposure',
    title: 'AI service exposed via NodePort without authentication',
    description: 'A NodePort service makes the AI endpoint reachable on every cluster node without requiring authentication. This allows unauthenticated access to the AI workload from the host network.',
    severity: 'high',
    category: 'exposed_endpoint',
    cvss_score: 8.2,
    remediation: 'Replace NodePort with ClusterIP. Expose externally only via an authenticated Ingress with TLS.',
    asset_types: ['mcp_server', 'model_server'],
    source: 'k8s',
  },
  {
    id: 'azure_public_no_acls',
    title: 'Azure AI resource publicly accessible with no network restrictions',
    description: 'publicNetworkAccess is enabled and no network ACLs are configured. Any client on the internet can reach this AI endpoint. For services processing sensitive text, PII, or proprietary data, unrestricted public access is a critical exposure risk.',
    severity: 'high',
    category: 'exposed_endpoint',
    cvss_score: 8.2,
    remediation: 'Set publicNetworkAccess to Disabled and configure a private endpoint, or add IP allowlist rules and VNet restrictions under networkAcls.',
    asset_types: ['llm_api_endpoint', 'model_server', 'cloud_ai_service'],
    source: 'azure',
  },
  {
    id: 'azure_local_auth_enabled',
    title: 'Azure AI resource allows API key authentication',
    description: 'disableLocalAuth is false, meaning API key-based authentication is active. A leaked key grants full access with no identity tracing, no conditional access enforcement, and no MFA protection.',
    severity: 'medium',
    category: 'missing_auth',
    cvss_score: 6.5,
    remediation: "Set disableLocalAuth: true to enforce Azure Active Directory authentication only. Assign callers the 'Cognitive Services User' role via RBAC.",
    asset_types: ['llm_api_endpoint', 'model_server', 'cloud_ai_service'],
    source: 'azure',
  },
  {
    id: 'azure_no_network_isolation',
    title: 'Azure AI resource has no network isolation',
    description: 'No network ACLs or private endpoints are configured. The AI endpoint accepts requests from any source IP. A compromised key allows exfiltration of AI responses or model probing from anywhere on the internet.',
    severity: 'high',
    category: 'no_network_policy',
    cvss_score: 7.5,
    remediation: 'Configure networkAcls with an IP allowlist restricted to known clients, or deploy a private endpoint and disable public network access entirely.',
    asset_types: ['llm_api_endpoint', 'model_server', 'cloud_ai_service'],
    source: 'azure',
  },
  {
    id: 'azure_no_private_endpoint',
    title: 'Azure AI resource has no private endpoint',
    description: 'All traffic to this AI service traverses the public internet. Data sent — including sensitive documents, PII, or proprietary content — is not confined to a private network path.',
    severity: 'medium',
    category: 'exposed_endpoint',
    cvss_score: 5.5,
    remediation: 'Create an Azure Private Endpoint for this resource and set publicNetworkAccess to Disabled to ensure all traffic remains within your virtual network.',
    asset_types: ['llm_api_endpoint', 'model_server', 'cloud_ai_service'],
    source: 'azure',
  },
  {
    id: 'azure_no_cmk',
    title: 'Azure AI resource uses platform-managed encryption only',
    description: 'Data at rest is encrypted with Microsoft-managed keys. For AI workloads processing regulated or sensitive data, this means no control over key rotation, no ability to revoke access by deleting a key, and no audit trail tied to your own Key Vault.',
    severity: 'low',
    category: 'insecure_config',
    cvss_score: 3.7,
    remediation: 'Configure a customer-managed key (CMK) in Azure Key Vault and assign it to this Cognitive Services resource under Encryption settings.',
    asset_types: ['llm_api_endpoint', 'model_server', 'cloud_ai_service'],
    source: 'azure',
  },
]

const CATEGORY_LABELS: Record<string, string> = {
  insecure_config: 'Insecure Config',
  over_permissioned: 'Over-Permissioned',
  missing_auth: 'Missing Auth',
  no_network_policy: 'No Network Policy',
  exposed_endpoint: 'Exposed Endpoint',
}

const ASSET_TYPE_LABELS: Record<string, string> = {
  mcp_server: 'MCP Server',
  agentic_framework: 'Agent',
  model_server: 'Model Server',
  llm_api_endpoint: 'LLM API',
  cloud_ai_service: 'Cloud AI',
}

export default function Policies() {
  const [selected, setSelected] = useState<Policy | null>(null)
  const [severityFilter, setSeverityFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')

  const filtered = POLICIES.filter(p =>
    (!severityFilter || p.severity === severityFilter) &&
    (!categoryFilter || p.category === categoryFilter)
  )

  const cvssColor = (v: number) =>
    v >= 9 ? 'text-red-400' : v >= 7 ? 'text-orange-400' : v >= 4 ? 'text-yellow-400' : 'text-green-400'

  return (
    <div className="flex flex-col gap-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="bg-specter-surface border border-specter-border text-slate-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
        </select>
        <select
          value={categoryFilter}
          onChange={e => setCategoryFilter(e.target.value)}
          className="bg-specter-surface border border-specter-border text-slate-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
        >
          <option value="">All Categories</option>
          {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <span className="ml-auto text-xs text-slate-500">{filtered.length} rules active</span>
      </div>

      {/* Rules grid */}
      <div className="flex flex-col gap-2">
        {filtered.map(policy => (
          <button
            key={policy.id}
            onClick={() => setSelected(policy)}
            className="text-left flex items-center gap-4 px-4 py-3 bg-specter-surface border border-specter-border rounded hover:border-specter-accent/40 transition-colors"
          >
            <div className="flex-1 min-w-0">
              <p className="text-sm text-white font-medium truncate">{policy.title}</p>
              <p className="text-xs text-slate-500 mt-0.5">{CATEGORY_LABELS[policy.category] ?? policy.category}</p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex gap-1">
                {policy.asset_types.map(t => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-specter-border text-slate-400 font-mono">
                    {ASSET_TYPE_LABELS[t] ?? t}
                  </span>
                ))}
              </div>
              <span className={`font-mono text-sm font-semibold w-8 text-right ${cvssColor(policy.cvss_score)}`}>
                {policy.cvss_score.toFixed(1)}
              </span>
              <SeverityBadge severity={policy.severity} />
            </div>
          </button>
        ))}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 z-40 flex justify-end">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setSelected(null)} />
          <div className="relative z-10 w-full max-w-lg bg-specter-surface border-l border-specter-border shadow-2xl flex flex-col overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-specter-border sticky top-0 bg-specter-surface z-10">
              <div className="flex items-center gap-3">
                <h2 className="text-white font-semibold text-base">Policy Rule</h2>
                <SeverityBadge severity={selected.severity} />
              </div>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white transition-colors">
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 px-6 py-5 flex flex-col gap-5">
              <div>
                <h3 className="text-lg font-bold text-white leading-snug">{selected.title}</h3>
                <p className="text-slate-400 text-sm mt-2 leading-relaxed">{selected.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: 'Category',   value: CATEGORY_LABELS[selected.category] ?? selected.category },
                  { label: 'CVSS Score', value: selected.cvss_score.toFixed(1) },
                  { label: 'Source',     value: selected.source.toUpperCase() },
                  { label: 'Rule ID',    value: selected.id },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
                    <p className="text-sm text-slate-200 font-medium font-mono">{value}</p>
                  </div>
                ))}
              </div>

              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Applies To</p>
                <div className="flex flex-wrap gap-1.5">
                  {selected.asset_types.map(t => (
                    <span key={t} className="text-xs px-2 py-1 rounded bg-specter-accent/10 text-specter-accent border border-specter-accent/20 font-mono">
                      {ASSET_TYPE_LABELS[t] ?? t}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Remediation</p>
                <div className="p-3 bg-green-500/5 border border-green-500/20 rounded">
                  <p className="text-sm text-slate-300 leading-relaxed">{selected.remediation}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
