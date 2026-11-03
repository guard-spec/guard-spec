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
      key: PS_APP_PASSWORD
{{- end -}}
