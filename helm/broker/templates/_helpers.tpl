{{- define "directory-broker.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "directory-broker.labels" -}}
app.kubernetes.io/name: directory-broker
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
