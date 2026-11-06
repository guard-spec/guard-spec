{{- define "guard-spec.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "guard-spec.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels; call with (dict "root" $ "component" "gateway"). */}}
{{- define "guard-spec.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "guard-spec.image" -}}
{{- printf "%s:%s" .image.repository (default .root.Chart.AppVersion .image.tag) -}}
{{- end -}}

{{/* repository:tag, or repository:tag@digest when .image.digest is set. */}}
{{- define "guard-spec.imageDigest" -}}
{{- $ref := printf "%s:%s" .repository .tag -}}
{{- with .digest }}{{ $ref = printf "%s@%s" $ref . }}{{ end -}}
{{- $ref -}}
{{- end -}}

{{/* An image whose empty repository and tag fall back to the gateway's. */}}
{{- define "guard-spec.gatewayDerivedImage" -}}
{{- $img := dict "repository" (default .root.Values.gateway.image.repository .image.repository) "tag" (default .root.Values.gateway.image.tag .image.tag) -}}
{{- include "guard-spec.image" (dict "root" .root "image" $img) -}}
{{- end -}}

{{/* Non-empty when the gateway has a PersistentVolumeClaim for the models:
an existing claim, or the chart's own PVC. */}}
{{- define "guard-spec.modelsClaimUsed" -}}
{{- if or .Values.models.existingClaim .Values.models.persistence.enabled -}}true{{- end -}}
{{- end -}}

{{/* Non-empty when the gateway mounts a models volume at /models: a claim,
or an emptyDir filled by models.pull. Otherwise nothing is mounted, so the
models inside guard-spec-gateway-full stay visible. */}}
{{- define "guard-spec.modelsVolume" -}}
{{- if or (include "guard-spec.modelsClaimUsed" .) .Values.models.pull.enabled -}}true{{- end -}}
{{- end -}}

{{/* serviceAccountName of the gateway and control plane pods, or "" for the
namespace default. */}}
{{- define "guard-spec.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "guard-spec.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* topologySpreadConstraints; a constraint without labelSelector gets the
component's selector labels. Call with (dict "root" $ "component" "gateway"
"constraints" list). */}}
{{- define "guard-spec.topologySpread" -}}
{{- $sel := include "guard-spec.selector" (dict "root" .root "component" .component) | fromYaml -}}
{{- $out := list -}}
{{- range .constraints -}}
{{- $c := deepCopy . -}}
{{- if not (hasKey $c "labelSelector") -}}
{{- $_ := set $c "labelSelector" (dict "matchLabels" $sel) -}}
{{- end -}}
{{- $out = append $out $c -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* Pod metadata of a component: chart labels, component, podLabels and
podAnnotations. Call with (dict "root" $ "component" "gateway"). */}}
{{- define "guard-spec.podMetadata" -}}
labels:
  {{- include "guard-spec.labels" .root | nindent 2 }}
  app.kubernetes.io/component: {{ .component }}
  {{- with .root.Values.podLabels }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- with .root.Values.podAnnotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "guard-spec.modelsClaim" -}}
{{- if .Values.models.existingClaim -}}
{{- .Values.models.existingClaim -}}
{{- else -}}
{{- printf "%s-models" (include "guard-spec.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Environment shared by both services. */}}
{{- define "guard-spec.commonEnv" -}}
- name: GUARD_ENV
  value: {{ .Values.guardEnv | quote }}
- name: DATABASE_URL
  value: {{ required "externalDatabase.url is required" .Values.externalDatabase.url | quote }}
- name: PGPASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ required "existingSecret is required" .Values.existingSecret }}
      key: {{ .Values.appPasswordKey | default "GUARDSPEC_APP_PASSWORD" }}
{{- end -}}

{{/*
GATEWAY_URL of the control plane: controlPlane.gatewayURL, else this
release's gateway Service; "" when it is "-".
*/}}
{{- define "guard-spec.gatewayURL" -}}
{{- $u := .Values.controlPlane.gatewayURL -}}
{{- if eq $u "-" -}}
{{- else if $u -}}
{{- $u -}}
{{- else -}}
{{- printf "http://%s-gateway:%v" (include "guard-spec.fullname" .) .Values.gateway.service.port -}}
{{- end -}}
{{- end }}
