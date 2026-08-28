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

{{/*
Image helper that replaces the registry with a custom prefix if specified.
Usage: {{ include "signet.image" (dict "image" .Values.image "registryPrefix" .Values.registryPrefix) }}
*/}}
{{- define "signet.image" -}}
{{- $image := .image -}}
{{- $registryPrefix := .registryPrefix -}}
{{- if $registryPrefix -}}
  {{- if hasPrefix "docker.io/" $image -}}
    {{- printf "%s/%s" $registryPrefix (trimPrefix "docker.io/" $image) -}}
  {{- else if hasPrefix "ghcr.io/" $image -}}
    {{- printf "%s/%s" $registryPrefix (trimPrefix "ghcr.io/" $image) -}}
  {{- else if hasPrefix "quay.io/" $image -}}
    {{- printf "%s/%s" $registryPrefix (trimPrefix "quay.io/" $image) -}}
  {{- else if hasPrefix "registry.k8s.io/" $image -}}
    {{- printf "%s/%s" $registryPrefix (trimPrefix "registry.k8s.io/" $image) -}}
  {{- else if contains "/" $image -}}
    {{- $parts := splitList "/" $image -}}
    {{- if gt (len $parts) 2 -}}
      {{- printf "%s/%s" $registryPrefix (join "/" (rest $parts)) -}}
    {{- else -}}
      {{- printf "%s/%s" $registryPrefix $image -}}
    {{- end -}}
  {{- else -}}
    {{- printf "%s/%s" $registryPrefix $image -}}
  {{- end -}}
{{- else -}}
  {{- $image -}}
{{- end -}}
{{- end -}}
