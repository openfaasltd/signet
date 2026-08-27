{{- define "signet.fullname" -}}
{{- $n := printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- if eq .Release.Name .Chart.Name -}}
{{- $n = .Chart.Name -}}
{{- end -}}
{{- $n -}}
{{- end -}}

{{- define "signet.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "signet.labels" -}}
app.kubernetes.io/name: {{ include "signet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- /*
  signet.masterKey returns the 32-byte master key. If the operator supplied
  .Values.masterKey use it, otherwise generate a random one on the first
  render and persist it via resource-policy: keep so it stays stable across
  upgrades. The key is always mounted as a file, never an env var.
*/ -}}
{{- define "signet.masterKey" -}}
{{- if .Values.masterKey -}}
{{- .Values.masterKey -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}

{{- define "signet.adminToken" -}}
{{- if .Values.adminToken -}}
{{- .Values.adminToken -}}
{{- else -}}
{{- randAlphaNum 43 -}}
{{- end -}}
{{- end -}}
