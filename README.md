# dnsstats

A tool for collecting and analyzing DNS statistics, with results forwarded to Splunk for further analysis.

## Description

dnsstats helps you monitor and analyze DNS query patterns, response times, and server performance metrics.
dnsstats runs as a Kubernetes CronJob and can be configured with custom parameters to suit your needs.

## Features

- DNS query monitoring
- Response time tracking
- Statistics aggregation
- Performance metrics

## ArgoCD Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: dnsstat-default
  namespace: argocd
spec:
  project: default
  source:
    path: .
    repoURL: oci://ncr.sky.nhn.no/ghcr/norskhelsenett/helm/dnsstats
    targetRevision: 1.*
    helm:
      valueFiles:
          - values.yaml
      parameters:
      - name: cronjob.identifier
        value: "default"
      - name: cronjob.schedule
        value: "*/1 * * * *"
      - name: settings.description
        value: "dns-benchmark"
      - name: settings.domain
        value: "example.com"
      - name: settings.datacenter
        value: "no-central-az1"
      - name: settings.platform
        value: "vitistack"
      - name: settings.servers
        value: ["10.246.196.76","10.245.248.76"]
      - name: settings.qps
        value: 50
      - name: settings.duration
        value: 10
      - name: settings.timeout
        value: 1500
      - name: splunk.token
        value: "46346-23423-56456-24525"
      - name: alarmathan.environment
        value: "prod"
      - name: alarmathan.cluster
        value: "xxx-xxx-xxx"
      - name: alarmathan.service_id
        value: 754
      - name: alarmathan.team
        value: "Driftsteam xxx"
  destination:
    server: "https://kubernetes.default.svc"
    namespace: gatewayapi-securitypolicy-system
  syncPolicy:
      automated:
          selfHeal: true
          prune: true
      syncOptions:
      - CreateNamespace=true
```