{{/* vim: set filetype=mustache: */}}

{{/*
Naming
*/}}

{{- define "druid.name" -}}
{{ .Values.hostedId }}-{{ .Release.Name }}
{{- end -}}

{{- define "druid.component.name" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{ include "druid.name" $ctx }}-druid-{{ $component }}
{{- end -}}

{{/*
Labels & Annotations
*/}}

{{/*
Required resource-tagging taxonomy (nanohype/standards/resource-tagging, required
tier) emitted on every object, then the chart's extra .Values.labels. The org
dimensions mirror the values landing-zone stamps on the druid AWS substrate
(CostCenter/BusinessUnit/DataClassification/Compliance/Team) so the k8s labels and
the cloud tags describe the same resource identically. app.kubernetes.io/component
is role-specific and added in druid.component.labels / druid.task.labels instead.
*/}}
{{- define "common.labels" }}
app.kubernetes.io/managed-by: {{ .Values.managedBy | default "argocd" | quote }}
platform.nanohype.dev/environment: {{ .Values.environment | quote }}
platform.nanohype.dev/project: {{ .Values.project | quote }}
platform.nanohype.dev/repository: {{ .Values.repository | quote }}
platform.nanohype.dev/team: {{ .Values.team | quote }}
platform.nanohype.dev/cost-center: {{ .Values.costCenter | quote }}
platform.nanohype.dev/business-unit: {{ .Values.businessUnit | quote }}
platform.nanohype.dev/data-classification: {{ .Values.dataClassification | quote }}
platform.nanohype.dev/compliance: {{ .Values.compliance | quote }}
{{- range $k, $v := .Values.labels }}
{{ $k | quote }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- define "common.annotations" -}}
{{- range $k, $v := .Values.annotations }}
{{ $k | quote }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- define "druid.component.labels" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- include "common.labels" $ctx }}
app.kubernetes.io/component: {{ $component | quote }}
{{ $ctx.Values.domain }}/version: {{ $ctx.Values.version }}
{{- $componentValues := index $ctx.Values $component -}}
{{- range $k, $v := $componentValues.metadata.labels }}
{{ $k | quote }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- define "druid.component.annotations" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- include "common.annotations" $ctx }}
{{- $componentValues := index $ctx.Values $component -}}
{{- range $k, $v := $componentValues.metadata.annotations }}
{{ $k | quote }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{/*
Selector labels. Only the component label — the {domain}/name label already
reaches every resource through common.labels, and emitting it here too would
render the same map key twice wherever templates combine component.labels
with match.labels.
*/}}
{{- define "druid.component.match.labels" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{ $ctx.Values.domain }}/component: {{ include "druid.component.name" (list $component $ctx) }}
{{- end -}}

{{/*
Node
*/}}

{{- define "druid.node.selector" -}}
kubernetes.io/arch: amd64
kubernetes.io/os: linux
karpenter.sh/capacity-type: on-demand
{{- end -}}

{{- define "druid.node.labels" -}}
{{ .Values.domain }}/category: analytics
{{ .Values.domain }}/type: node
{{ .Values.domain }}/part-of: druid
{{- end -}}

{{- define "druid.node.requirements" -}}
- key: "kubernetes.io/arch"
  operator: In
  values: ["amd64"]
- key: "kubernetes.io/os"
  operator: In
  values: ["linux"]
{{- end -}}

{{- define "druid.component.node.selector" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- include "druid.node.selector" $ctx }}
{{- $componentValues := index $ctx.Values $component }}
{{ toYaml $componentValues.node.selector }}
eks.amazonaws.com/nodegroup: {{ include "druid.component.name" (list $component $ctx) }}-node
{{- end -}}

{{/*
Security — per-component service account
*/}}

{{- define "druid.security" -}}
{{- $saName := index . 0 -}}
{{- $ctx := index . 1 -}}
automountServiceAccountToken: true
serviceAccountName: {{ $saName }}
securityContext:
{{- toYaml $ctx.Values.securityContext | nindent 2 }}
{{- end -}}

{{/*
Container-level hardening, shared by every Druid container. The JVM runs as
uid 1000 (pod securityContext), never needs privilege escalation, holds no
capabilities (all listen ports are >1024), and is happy under the runtime's
default seccomp profile.
*/}}
{{- define "druid.container.security" -}}
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
{{- end -}}

{{/*
Environment — computed from release name
*/}}

{{- define "druid.env" -}}
- name: AWS_REGION
  value: {{ .Values.region | quote }}
- name: HOSTNAME
  valueFrom:
    fieldRef:
      apiVersion: v1
      fieldPath: metadata.name
- name: POD_NAME
  valueFrom:
    fieldRef:
      apiVersion: v1
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      apiVersion: v1
      fieldPath: metadata.namespace
- name: DRUID_CLUSTER_ID
  value: {{ include "druid.name" . }}
- name: DRUID_S3_INDEXLOGS_BUCKET
  value: {{ .Values.s3.indexLogsBucket | quote }}
- name: DRUID_S3_DEEPSTORAGE_BUCKET
  value: {{ .Values.s3.deepStorageBucket | quote }}
- name: DRUID_S3_MSQ_BUCKET
  value: {{ .Values.s3.msqBucket | quote }}
- name: DRUID_METADATA_STORAGE_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-metadata
      key: username
- name: DRUID_METADATA_STORAGE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-metadata
      key: password
- name: DRUID_METADATA_STORAGE_DBNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-metadata
      key: dbname
- name: DRUID_METADATA_STORAGE_HOST
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-metadata
      key: host
- name: DRUID_METADATA_STORAGE_CONNECT_URI
  value: jdbc:postgresql://$(DRUID_METADATA_STORAGE_HOST)/$(DRUID_METADATA_STORAGE_DBNAME)
- name: DRUID_ADMIN_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-admin
      key: username
- name: DRUID_ADMIN_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-admin
      key: password
- name: DRUID_SYSTEM_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-system
      key: username
- name: DRUID_SYSTEM_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-druid-system
      key: password
- name: DRUID_TLS_KEYSTORE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "druid.name" . }}-keystore-password
      key: password
{{- with .Values.extraEnv }}
{{ . | toYaml }}
{{- end }}
{{- end -}}

{{/*
Volumes — base volumes computed from release name
*/}}

{{- define "druid.volumes" -}}
- name: druid-scratch
  emptyDir: {}
- name: druid-common-conf
  configMap:
    name: {{ include "druid.name" . }}-druid-common-conf
- name: druid-tls
  secret:
    secretName: {{ include "druid.name" . }}-druid-tls
    items:
      - key: keystore.p12
        path: client-keystore.p12
      - key: truststore.p12
        path: client-truststore.p12
      - key: tls.crt
        path: client.crt
      - key: keystore.p12
        path: server-keystore.p12
      - key: truststore.p12
        path: server-truststore.p12
      - key: tls.crt
        path: server.crt
{{- end -}}

{{- define "druid.volumeMounts" -}}
- mountPath: /opt/druid/conf/druid/cluster/_common
  name: druid-common-conf
  readOnly: true
- mountPath: /opt/druid/conf/druid/cluster/tls
  name: druid-tls
  readOnly: true
- mountPath: /var/druid
  name: druid-scratch
  readOnly: false
{{- end -}}

{{/*
Per-component volumes — adds component configmap to base volumes
*/}}

{{- define "druid.component.volumes" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- include "druid.volumes" $ctx }}
- name: druid-{{ $component }}-conf
  configMap:
    name: {{ include "druid.component.name" (list $component $ctx) }}-conf
{{- $componentValues := index $ctx.Values $component -}}
{{- with $componentValues.volumes }}
{{ . | toYaml }}
{{- end }}
{{- end -}}

{{- define "druid.component.volumeMounts" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- include "druid.volumeMounts" $ctx }}
{{- $componentValues := index $ctx.Values $component -}}
{{- with $componentValues.volumeMounts }}
{{ . | toYaml }}
{{- end }}
{{- end -}}

{{/*
Image
*/}}

{{- define "druid.image" -}}
image: "{{ .Values.image.uri }}"
imagePullPolicy: {{ .Values.image.pullPolicy }}
{{- end -}}

{{/*
JVM
*/}}

{{- define "druid.component.jvm" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- $componentValues := index $ctx.Values $component -}}
{{- if $componentValues.jvm }}
{{- printf "%s\n%s" ($ctx.Files.Get "common/jvm.config") $componentValues.jvm | toYaml }}
{{- else }}
{{- $ctx.Files.Get "common/jvm.config" | toYaml }}
{{- end }}
{{- end -}}

{{/*
Probes — (port, healthPath, readinessPath).

Every process in this chart (coordinator, overlord, broker, historical, router)
exposes /status/health — plus the broker/historical readiness endpoints — on its
service port, so all probes are real httpGet checks; none of the components
lacks an HTTP health surface, so there is no tcpSocket fallback. The cluster
runs TLS-only (druid.enablePlaintextPort=false), hence scheme HTTPS: the
kubelet skips certificate verification for HTTPS probes, so the internal CA is
fine, and Druid serves these paths unauthenticated (they are on its default
unsecured-path list) with client certs requested but not required.
*/}}

{{- define "druid.probes" -}}
{{- $port := index . 0 -}}
{{- $healthPath := index . 1 -}}
{{- $readinessPath := index . 2 -}}
livenessProbe:
  failureThreshold: 3
  httpGet:
    path: {{ $healthPath }}
    port: {{ $port }}
    scheme: HTTPS
  initialDelaySeconds: 180
  periodSeconds: 10
  successThreshold: 1
  timeoutSeconds: 5
readinessProbe:
  failureThreshold: 10
  httpGet:
    path: {{ $readinessPath }}
    port: {{ $port }}
    scheme: HTTPS
  initialDelaySeconds: 180
  periodSeconds: 10
  successThreshold: 1
  timeoutSeconds: 5
startupProbe:
  failureThreshold: 60
  httpGet:
    path: {{ $healthPath }}
    port: {{ $port }}
    scheme: HTTPS
  initialDelaySeconds: 60
  periodSeconds: 10
  successThreshold: 1
  timeoutSeconds: 5
{{- end -}}

{{/*
Ports
*/}}

{{- define "druid.ports" -}}
{{- $name := index . 0 -}}
{{- $port := index . 1 -}}
ports:
  - name: {{ $name }}
    containerPort: {{ $port }}
    protocol: TCP
  - name: prometheus
    containerPort: 9000
    protocol: TCP
{{- end -}}

{{- define "druid.service.ports" -}}
{{- $name := index . 0 -}}
{{- $port := index . 1 -}}
ports:
  - name: {{ $name }}
    port: {{ $port }}
  - name: prometheus
    port: 9000
{{- end -}}

{{/*
NodePool
*/}}

{{- define "druid.nodepool.spec" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- $componentValues := index $ctx.Values $component -}}
{{- $nodeName := include "druid.component.name" (list $component $ctx) -}}
spec:
  limits:
    {{- toYaml $componentValues.node.limits | nindent 4 }}
  disruption:
    {{- toYaml $componentValues.node.disruption | nindent 4 }}
  template:
    metadata:
      labels:
        {{- include "druid.node.labels" $ctx | nindent 8 }}
        eks.amazonaws.com/nodegroup: {{ $nodeName }}-node
    spec:
      requirements:
        - key: "eks.amazonaws.com/nodegroup"
          operator: In
          values: ["{{ $nodeName }}-node"]
        {{- include "druid.node.requirements" $ctx | nindent 8 }}
        {{- toYaml $componentValues.node.requirements | nindent 8 }}
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: {{ include "druid.name" $ctx }}-druid-nodeclass
{{- end -}}

{{/*
High availability — PodDisruptionBudget & topology spread

Both are parameterized by (list component ctx) like every other component helper
and reuse druid.component.match.labels for their selectors, so a PDB and a spread
constraint always target exactly the pods that role's Deployment/StatefulSet owns.
*/}}

{{/*
PodDisruptionBudget for a long-running role. Rendered ONLY when the role's pdb is
enabled AND its replicas > 1 — a PDB on a single replica can only ever wedge a
node drain (minAvailable:1 blocks the sole pod; maxUnavailable:1 is a no-op), so a
role scaled to 1 gets no PDB at all. The budget is expressed as maxUnavailable
(drain-safe at any replica count) by default; setting pdb.minAvailable switches to
that expression, and because rendering is gated on replicas>1 even a minAvailable
budget can never block the last pod. The leading document separator lets the
ranging poddisruptionbudget.yaml emit one PDB per HA role from a single template.
*/}}
{{- define "druid.component.pdb" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- $componentValues := index $ctx.Values $component -}}
{{- $pdb := $componentValues.pdb | default dict -}}
{{- $replicas := $componentValues.replicas | default 1 | int -}}
{{- if and $pdb.enabled (gt $replicas 1) }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "druid.component.name" (list $component $ctx) }}
  labels:
    {{- include "druid.component.labels" (list $component $ctx) | indent 4 }}
  annotations:
    {{- include "druid.component.annotations" (list $component $ctx) | indent 4 }}
spec:
  {{- if $pdb.minAvailable }}
  minAvailable: {{ $pdb.minAvailable }}
  {{- else }}
  maxUnavailable: {{ $pdb.maxUnavailable | default 1 }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "druid.component.match.labels" (list $component $ctx) | nindent 6 }}
{{- end }}
{{- end -}}

{{/*
Soft topology spread for a long-running role. whenUnsatisfiable is ScheduleAnyway
(overridable) so replicas PREFER to land in different zones/hosts for HA but a
single-zone or small dev cluster still schedules them rather than leaving pods
Pending. labelSelector reuses druid.component.match.labels so the skew is computed
over exactly this role's pods. topologyKeys / maxSkew / whenUnsatisfiable are
per-role knobs; the helper emits nothing when topologySpread.enabled is false.
*/}}
{{- define "druid.component.topologySpread" -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- $componentValues := index $ctx.Values $component -}}
{{- $ts := $componentValues.topologySpread | default dict -}}
{{- if $ts.enabled }}
{{- $keys := $ts.topologyKeys | default (list "topology.kubernetes.io/zone") }}
topologySpreadConstraints:
{{- range $key := $keys }}
  - maxSkew: {{ $ts.maxSkew | default 1 }}
    topologyKey: {{ $key }}
    whenUnsatisfiable: {{ $ts.whenUnsatisfiable | default "ScheduleAnyway" }}
    labelSelector:
      matchLabels:
        {{- include "druid.component.match.labels" (list $component $ctx) | nindent 8 }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Task (special case — nested under task.base)
*/}}

{{- define "druid.task.labels" -}}
{{- include "common.labels" . }}
app.kubernetes.io/component: task
{{ .Values.domain }}/version: {{ .Values.version }}
{{- range $k, $v := .Values.task.base.metadata.labels }}
{{ $k | quote }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- define "druid.task.annotations" -}}
{{- include "common.annotations" . }}
{{- range $k, $v := .Values.task.base.metadata.annotations }}
{{ $k | quote }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- define "druid.task.node.selector" -}}
{{- include "druid.node.selector" . }}
{{ toYaml .Values.task.base.node.selector }}
eks.amazonaws.com/nodegroup: {{ include "druid.name" . }}-druid-task-base-node
{{- end -}}

{{- define "druid.task.volumes" -}}
{{- include "druid.volumes" . }}
- name: task-conf
  configMap:
    name: {{ include "druid.name" . }}-druid-task-base-conf
{{- with .Values.task.base.volumes }}
{{ . | toYaml }}
{{- end }}
{{- end -}}

{{- define "druid.task.volumeMounts" -}}
{{- include "druid.volumeMounts" . }}
- name: task-conf
  mountPath: /opt/druid/conf/druid/cluster/master/coordinator-overlord
  readOnly: true
{{- with .Values.task.base.volumeMounts }}
{{ . | toYaml }}
{{- end }}
{{- end -}}

{{- define "druid.task.jvm" -}}
{{- if .Values.task.base.jvm }}
{{- printf "%s\n%s" (.Files.Get "common/jvm.config") .Values.task.base.jvm | toYaml }}
{{- else }}
{{- .Files.Get "common/jvm.config" | toYaml }}
{{- end }}
{{- end -}}
