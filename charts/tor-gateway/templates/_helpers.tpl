{{/*
Common helper templates for the tor-gateway chart.
*/}}

{{- define "tor-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tor-gateway.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tor-gateway.labels" -}}
app.kubernetes.io/name: {{ include "tor-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "tor-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tor-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: manager
{{- end -}}

{{- define "tor-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tor-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tor-gateway.managerImage" -}}
{{- $tag := default .Chart.AppVersion .Values.manager.image.tag -}}
{{- printf "%s:%s" .Values.manager.image.repository $tag -}}
{{- end -}}
