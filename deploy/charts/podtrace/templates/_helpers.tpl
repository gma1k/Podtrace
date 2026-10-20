{{/*
Chart name (sanitized).
*/}}
{{- define "podtrace.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Fully qualified app name — used as a prefix for rendered resources. Respects
fullnameOverride, releaseName, and the standard Helm Bitnami-style convention.
*/}}
{{- define "podtrace.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
Chart metadata label, typically used as `helm.sh/chart`.
*/}}
{{- define "podtrace.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Common labels applied to every rendered resource.
*/}}
{{- define "podtrace.labels" -}}
helm.sh/chart: {{ include "podtrace.chart" . }}
{{ include "podtrace.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: podtrace
{{- end }}

{{/*
Selector labels — a stable subset of "podtrace.labels" safe for use under
selector fields (Deployment, Service, DaemonSet).
*/}}
{{- define "podtrace.selectorLabels" -}}
app.kubernetes.io/name: {{ include "podtrace.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolved system namespace. The operator, agent DaemonSet and session Jobs
all live here regardless of the Helm release namespace.
*/}}
{{- define "podtrace.systemNamespace" -}}
{{- default "podtrace-system" .Values.namespace.name -}}
{{- end }}

{{/*
Resolved container image reference. Prefers an immutable digest when
image.digest is set (repository@sha256:...); otherwise falls back to
repository:tag. Pinning by digest closes the mutable-tag supply-chain gap for
the root+CAP_SYS_ADMIN workload.

image.appVersionDigest is written by the release job: the digest of the
appVersion image it built. It pins the default reference only, so a chosen
tag, a chosen digest or a mirror repository (which may hold a re-pushed image
with another digest) behave exactly as they would without it.
*/}}
{{- define "podtrace.image" -}}
{{- $repo := .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else if .Values.image.tag -}}
{{- printf "%s:%s" $repo .Values.image.tag -}}
{{- else if and .Values.image.appVersionDigest (eq $repo "ghcr.io/gma1k/podtrace") -}}
{{- printf "%s:%s@%s" $repo .Chart.AppVersion .Values.image.appVersionDigest -}}
{{- else -}}
{{- printf "%s:%s" $repo .Chart.AppVersion -}}
{{- end -}}
{{- end }}
