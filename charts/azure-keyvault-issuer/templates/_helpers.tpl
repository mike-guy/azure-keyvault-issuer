{{/* The chart's name. */}}
{{- define "akvi.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* The name that prefixes every resource. */}}
{{- define "akvi.fullname" -}}
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

{{/* The chart's name and version, for the helm.sh/chart label. */}}
{{- define "akvi.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Labels on every resource. */}}
{{- define "akvi.labels" -}}
helm.sh/chart: {{ include "akvi.chart" . }}
{{ include "akvi.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Labels that pick out the controller's pods. */}}
{{- define "akvi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "akvi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}

{{/* The controller's ServiceAccount name. */}}
{{- define "akvi.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "akvi.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* The controller image: repository, then the digest if set, else the tag. */}}
{{- define "akvi.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
Fails if names lists the controller's own ServiceAccount. A ServiceAccount the
controller may mint tokens for is one an issuer can borrow the identity of, and
the controller's own carries the ambient identity that ClusterIssuers and
namespaced Issuers must not reach by naming it. Call with a dict of "ctx" (the
root context), "namespace" and "names".
*/}}
{{- define "akvi.refuseOwnServiceAccount" -}}
{{- if eq .namespace .ctx.Release.Namespace }}
{{- if has (include "akvi.serviceAccountName" .ctx) .names }}
{{- fail (printf "the controller's own ServiceAccount %q must not be listed for token access: it would let issuers use the controller's ambient identity" (include "akvi.serviceAccountName" .ctx)) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
The names the controller may use, as YAML keyed by namespace. Call with a dict
of "ctx" (the root context) and "field": "serviceAccounts" for the
ServiceAccounts it may mint tokens for, or "secrets" for the Secrets it may
read. The ClusterIssuer entry and every tenantAccess entry are merged per
namespace, so each namespace gets one Role and RoleBinding of each kind even
when entries share it. Entries with no names are dropped: a Role with an empty
resourceNames list would cover every object of its type.
*/}}
{{- define "akvi.namedAccess" -}}
{{- $ctx := .ctx }}
{{- $field := .field }}
{{- $access := dict }}
{{- $entries := list (dict "namespace" (include "akvi.clusterNamespace" $ctx) "names" (get $ctx.Values.clusterIssuer $field)) }}
{{- range $ctx.Values.tenantAccess }}
{{- $entries = append $entries (dict "namespace" .namespace "names" (get . $field)) }}
{{- end }}
{{- range $entries }}
{{- if .names }}
{{- if eq $field "serviceAccounts" }}
{{- $_ := include "akvi.refuseOwnServiceAccount" (dict "ctx" $ctx "namespace" .namespace "names" .names) }}
{{- end }}
{{- $_ := set $access .namespace (concat (get $access .namespace | default list) .names) }}
{{- end }}
{{- end }}
{{- $merged := dict }}
{{- range $ns, $names := $access }}
{{- $_ := set $merged $ns (uniq $names | sortAlpha) }}
{{- end }}
{{- toYaml $merged }}
{{- end }}

{{/* The namespace in which ClusterIssuer ServiceAccount and Secret references, and the leader election lease, live. */}}
{{- define "akvi.clusterNamespace" -}}
{{- default .Release.Namespace .Values.controller.clusterResourceNamespace }}
{{- end }}

{{/*
The namespaced Roles the controller needs, as YAML: the leader election Role
in the cluster resource namespace, one token Role per namespace with
ServiceAccounts, and one Secret Role per namespace with Secrets (see
akvi.namedAccess). role.yaml and rolebinding.yaml both render from this list,
so each Role and its RoleBinding share a name and namespace.
*/}}
{{- define "akvi.namespacedRoles" -}}
{{- $fullname := include "akvi.fullname" . }}
{{- $roles := list (dict "name" (printf "%s-leader-election" $fullname) "namespace" (include "akvi.clusterNamespace" .) "kind" "lease") }}
{{- range $namespace, $names := include "akvi.namedAccess" (dict "ctx" . "field" "serviceAccounts") | fromYaml }}
{{- $roles = append $roles (dict "name" (printf "%s-token" $fullname) "namespace" $namespace "kind" "token" "names" $names) }}
{{- end }}
{{- range $namespace, $names := include "akvi.namedAccess" (dict "ctx" . "field" "secrets") | fromYaml }}
{{- $roles = append $roles (dict "name" (printf "%s-secrets" $fullname) "namespace" $namespace "kind" "secret" "names" $names) }}
{{- end }}
{{- toYaml (dict "roles" $roles) }}
{{- end }}
