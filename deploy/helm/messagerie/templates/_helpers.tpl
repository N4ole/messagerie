{{- define "messagerie.fullname" -}}{{ printf "%s" .Release.Name | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- define "messagerie.labels" -}}
app.kubernetes.io/name: messagerie
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "messagerie.selector" -}}
app.kubernetes.io/name: messagerie
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}
{{- define "messagerie.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}
{{- define "messagerie.dbSecret" -}}
{{- if .Values.database.cloudnativepg.enabled -}}{{ include "messagerie.fullname" . }}-db-app{{- else -}}{{ required "database.existingUriSecret requis sans CloudNativePG" .Values.database.existingUriSecret }}{{- end -}}
{{- end -}}
{{- define "messagerie.podSecurity" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  seccompProfile: { type: RuntimeDefault }
{{- end -}}
{{- define "messagerie.containerSecurity" -}}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: [ALL] }
{{- end -}}
{{- define "messagerie.env" -}}
- name: DATABASE_URL_FILE
  value: /run/secrets/db/uri
- name: MSG_SERVER_SECRET_FILE
  value: /run/secrets/app/server-secret
- name: MSG_SITE_NAME
  value: {{ .Values.site.name | quote }}
- name: MSG_WEBAUTHN_RP_ID
  value: {{ .Values.site.domain | quote }}
- name: MSG_WEBAUTHN_ORIGIN
  value: {{ printf "https://%s" .Values.site.domain | quote }}
{{- if .Values.site.onionOnly }}
- name: MSG_WEB_ONION_ONLY
  value: "1"
{{- end }}
{{- if .Values.federation.peers }}
- name: MSG_FEDERATION_PEERS
  value: /etc/messagerie/peers.json
{{- end }}
{{- if .Values.federation.proxy }}
- name: MSG_FEDERATION_PROXY
  value: {{ .Values.federation.proxy | quote }}
{{- end }}
{{- end -}}
{{- define "messagerie.volumeMounts" -}}
- { name: db, mountPath: /run/secrets/db, readOnly: true }
- { name: app, mountPath: /run/secrets/app, readOnly: true }
{{- if .Values.federation.peers }}
- { name: peers, mountPath: /etc/messagerie, readOnly: true }
{{- end }}
{{- end -}}
{{- define "messagerie.volumes" -}}
- name: db
  secret: { secretName: {{ include "messagerie.dbSecret" . }}, items: [{ key: uri, path: uri }] }
- name: app
  secret: { secretName: {{ .Values.existingSecret }} }
{{- if .Values.federation.peers }}
- name: peers
  configMap: { name: {{ include "messagerie.fullname" . }}-peers }
{{- end }}
{{- end -}}
