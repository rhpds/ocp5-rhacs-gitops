{{/*
Custom hostname (quay.apps.<subdomain>) requires an unmanaged Route.
The Operator forbids tls:managed in that case, and treats
EXTERNAL_TLS_TERMINATION in the config bundle as TLS-component config, so
tls must be unmanaged and we must supply ssl.cert/ssl.key.

Argo CD helm lookup is empty in the repo-server, so certs are generated at
template time. ignoreDifferences on the Secret data + Route dest CA keeps the
first-applied pair so later syncs do not rotate the CA out from under the pods.
*/}}
{{- define "quay.serverHostname" -}}
{{- if .Values.clusterSubdomain -}}
{{ .Values.routeHost | default "quay" }}.{{ .Values.clusterSubdomain }}
{{- end -}}
{{- end }}

{{- define "quay.initTLS" -}}
{{- if and .Values.clusterSubdomain (not .quayTLSReady) }}
{{- $server := include "quay.serverHostname" . }}
{{- $svc := printf "%s-quay.%s.svc" .Values.registry.name .Release.Namespace }}
{{- $svcFQDN := printf "%s-quay.%s.svc.cluster.local" .Values.registry.name .Release.Namespace }}
{{- $ca := genCA "quay-reencrypt-ca" 3650 }}
{{- $cert := genSignedCert $server nil (list $server $svc $svcFQDN) 3650 $ca }}
{{- $_ := set . "quayCACert" $ca.Cert }}
{{- $_ := set . "quayTLSCert" $cert.Cert }}
{{- $_ := set . "quayTLSKey" $cert.Key }}
{{- $_ := set . "quayTLSReady" true }}
{{- end -}}
{{- end }}
