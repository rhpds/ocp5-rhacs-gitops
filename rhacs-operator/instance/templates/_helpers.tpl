{{/*
Expand the name of the chart.
*/}}
{{- define "acs-instance.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Determine target namespace
*/}}
{{- define "acs-instance.namespace" -}}
{{- if .Values.namespace }}
{{- printf "%s" .Values.namespace }}
{{- else }}
{{- printf "%s" .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
ArgoCD Syncwave
*/}}
{{- define "acs-instance.argocd-syncwave" -}}
{{- if .Values.argocd }}
{{- if and (.Values.argocd.syncwave) (.Values.argocd.enabled) -}}
argocd.argoproj.io/sync-wave: "{{ .Values.argocd.syncwave }}"
{{- else }}
{{- "{}" }}
{{- end }}
{{- else }}
{{- "{}" }}
{{- end }}
{{- end }}
