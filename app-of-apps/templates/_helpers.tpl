{{/*
Common sync policy for child Applications.
Provides automated sync with prune, selfHeal, retry with backoff, and standard syncOptions.
*/}}
{{- define "app-of-apps.syncPolicy" -}}
syncPolicy:
  automated:
    prune: true
    selfHeal: true
  retry:
    backoff:
      duration: 5s
      factor: 2
      maxDuration: 1m0s
    # Keep this small. A Running retry pins the SHA from when the
    # operation started, so later commits will not apply until it ends.
    limit: 5
  syncOptions:
    - CreateNamespace=true
    - RespectIgnoreDifferences=true
    - SkipDryRunOnMissingResource=true
{{- end }}

{{/*
Returns the operator catalog source name.
When catalog snapshot is enabled, returns the custom CatalogSource name;
otherwise returns "redhat-operators".
*/}}
{{- define "app-of-apps.operatorSource" -}}
{{- if .Values.catalogSource.enabled -}}
{{ .Values.catalogSource.name }}
{{- else -}}
redhat-operators
{{- end -}}
{{- end -}}

{{/*
Common Application metadata with foreground finalizer.
Usage: {{ include "app-of-apps.metadata" (dict "name" "my-app" "namespace" .Values.argocd.namespace "syncWave" "0") }}
*/}}
{{- define "app-of-apps.metadata" -}}
metadata:
  name: {{ .name }}
  namespace: {{ .namespace }}
  labels:
    app.kubernetes.io/part-of: app-of-apps
  annotations:
    argocd.argoproj.io/sync-wave: "{{ .syncWave }}"
  finalizers:
    - resources-finalizer.argocd.argoproj.io/foreground
{{- end }}
