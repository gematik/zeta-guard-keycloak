# Create configuration

```shell
    helm template local zeta-guard -f zeta-guard/local/values.yaml
```

# Deploy in Kubernetes

```shell
     helm install local zeta-guard -f zeta-guard/local/values.yaml --create-namespace
```
