# dnsstats

A tool for collecting and analyzing DNS statistics.

## Description

dnsstats helps you monitor and analyze DNS query patterns, response times, and server performance metrics.

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
  name: gatewayapi-securitypolicy-operator
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