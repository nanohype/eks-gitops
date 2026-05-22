# mcp-tunnel

Exposes a private, in-cluster MCP server to Claude Managed Agents over an
outbound-only tunnel — no inbound ports, no public exposure. It wraps
Anthropic's [MCP tunnels](https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview)
Helm chart: a single Deployment running `cloudflared` (the outbound tunnel
agent) and the routing proxy (terminates inner TLS, validates upstream IPs,
routes by hostname to the in-cluster MCP server).

## Opt-in

This addon is **not** wired into an ApplicationSet. The nanohype factory
runs no private MCP server, so it ships as a template — the factory itself
does not deploy it. Enable it only if you have a private MCP server to
expose.

MCP tunnels is an Anthropic **research preview** —
[request access](https://claude.com/form/claude-managed-agents) first.

## Enable it

1. **Create a tunnel** in the Claude Console
   ([Create a tunnel](https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/console#create-a-tunnel)).
   Record the tunnel id (`tnl_…`) and the tunnel domain.

2. **Set up authentication.** Two modes:
   - **Workload Identity Federation** — the default in `values.yaml`. Register
     the cluster's OIDC issuer and create a federation rule scoped to
     `org:manage_tunnels`; the chart's setup Job mints the tunnel token and
     manages the certificate. See
     [Use WIF with Kubernetes](https://platform.claude.com/docs/en/manage-claude/wif-providers/kubernetes).
   - **Manual** — set `setup.enabled: false`, generate a CA + server
     certificate, register the CA in the Console, and create the
     `mcp-tunnel-token` and `mcp-tunnel-cert` Secrets. See
     [Deploy with Helm](https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/deploy-helm).

3. **Fill in `values.yaml`** — replace the `tnl_…` / `fdrl_…` /
   organization-id placeholders, and add a `gateway.config.routes` entry for
   each MCP server you expose.

4. **Wire it into ArgoCD** — add this entry to the `list` generator in
   `applicationsets/addons-networking.yaml`:

   ```yaml
   - appName: mcp-tunnel
     namespace: mcp-tunnel
     chartRepo: oci://us-docker.pkg.dev/anthropic-public-registry/charts
     chart: mcp-tunnel
     chartVersion: "1.0.0"
     path: addons/networking/mcp-tunnel
     syncWave: "1"
   ```

Once the tunnel is active, each routed server is reachable from Claude at
`https://<subdomain>.<tunnel-domain>/<path>` — pass that URL to a Managed
Agents session or the MCP connector. fab registers tunneled servers through
its `FAB_MCP_TUNNEL` env knob (see fab's `src/mcp.ts`).
