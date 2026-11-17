{{/*
The chart name, which nameOverride replaces.
*/}}
{{- define "azure-keyvault-issuer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The full name of the release's resources. A release name that already contains the chart name is not repeated.
*/}}
{{- define "azure-keyvault-issuer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
The chart name and version, for the helm.sh/chart label.
*/}}
{{- define "azure-keyvault-issuer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The labels that select the controller's pods. They never change after install, as a Deployment's selector is immutable.
*/}}
{{- define "azure-keyvault-issuer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "azure-keyvault-issuer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The labels on every resource.
*/}}
{{- define "azure-keyvault-issuer.labels" -}}
helm.sh/chart: {{ include "azure-keyvault-issuer.chart" . }}
{{ include "azure-keyvault-issuer.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
The name of the ServiceAccount the controller runs as.
*/}}
{{- define "azure-keyvault-issuer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "azure-keyvault-issuer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The image reference. A digest wins over a tag, and the tag defaults to the appVersion.
*/}}
{{- define "azure-keyvault-issuer.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
The namespace ClusterIssuer Secrets and ServiceAccounts are found in.
*/}}
{{- define "azure-keyvault-issuer.clusterResourceNamespace" -}}
{{- default .Release.Namespace .Values.clusterResourceNamespace }}
{{- end }}
