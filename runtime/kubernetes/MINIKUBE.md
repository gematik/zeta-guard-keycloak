# Before deploying to minikube

Set new DOCKER_HOST and the like to use minikube's docker daemon and rebuild the image.

```shell
    eval `minikube docker-env`

    mvn clean install -DskipTests
```

# Prepare Kubernetes configuration

```shell
    kubectl apply -f 010-Namespace.yaml -f 020-Secrets.yaml -f 030-Storage.yaml
```
# Deploy Postgres

```shell
    kubectl apply -f 040-Postgres.yaml
```

# Deploy Keycloak

```shell
    kubectl apply -f 050-Keycloak.yaml
```

# Connect to Postgres DB and Keycloak

```shell
   kubectl port-forward -n zeta-guard service/postgres 15432:5432
   kubectl port-forward -n zeta-guard service/keycloak-zeta 18080:8080
```

Login at http://localhost:18080/admin/master/console/

## Minikube's way...

```
    minikube service -n zeta-guard postgres --url
    minikube service -n zeta-guard keycloak-zeta --url
```
