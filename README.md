# OCP5 RHACS GitOps

Helm charts for the hosted environment, deployed via Argo CD's app-of-apps pattern.

## Structure

- `app-of-apps/` — Root chart that creates child Argo CD Applications
- `rhacs-operator/` — Red Hat Advanced Cluster Security (operator + Central instance)
- `rhacs-virt/` — OpenShift Virtualization VM used by ACS labs
- `rhacs-mcp-server-prereqs/` — CA copy and secrets for the ACS MCP server
- `rhacs-mcp-ols-token/` — Lightspeed token wiring for ACS MCP
- `rhacs-microservices-demo/` — Demo microservices scanned by ACS
- `roadshow-prereqs/` — Cluster-wide roadshow extras (Compliance Operator, collector ConfigMap, ACME RBAC, audit retention, privileged SCC for ACS demo-apps)
- Argo Application `roadshow-demo-apps` — recursive apply of `mfosterrox/demo-apps` `kubernetes-manifests/`
- `lightwell-tssc/` — Nested Argo Applications for the [Lightwell TSSC workshop](https://github.com/rhpds/lightwell-tssc-workshop) (RHTAS, RHTPA, Gitea, Nexus, Pipelines, RHDH). Does not reinstall RHACS or Showroom.

## Usage

The automation repo creates a single Argo CD Application pointing at `app-of-apps/`.
Argo CD renders the Helm chart, which generates child Applications for each component.
