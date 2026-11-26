# Kubernetes example

A minimal single-replica deployment of `jauntd`. It is an example, not a supported chart. Read [docs/operations.md](../../docs/operations.md) before you run it for real.

| File | Contents |
|---|---|
| `namespace.yaml` | the `jaunt` namespace |
| `config.yaml` | `jauntd.yaml` and a sample policy as ConfigMaps |
| `storage.yaml` | a 20 GiB volume claim for the SQLite database, the CA keys and the recordings |
| `ca-init-job.yaml` | a one-off Job that runs `jauntd ca init --generate-identity` |
| `deployment.yaml` | one replica, `Recreate` strategy, probes on `/healthz` |
| `service.yaml` | ports 8443 (HTTP behind your TLS front), 8444 (agents, TLS 1.3 with client certificates) and 2222 (SSH gate) |

The Secret `jaunt-secrets` is not in the repository. Create it with the OIDC client secret before you apply the deployment:

```sh
kubectl -n jaunt create secret generic jaunt-secrets --from-file=oidc-client-secret=./oidc-client-secret
```

Port 8443 speaks plain HTTP: put a TLS terminator in front of it (an Ingress or a Gateway). Port 8444 terminates TLS inside `jauntd` and asks the agent for a client certificate, so a load balancer must pass it through at layer 4 (TLS passthrough on the SNI name in `agent_endpoint`); a terminating proxy breaks it. Port 2222 carries SSH and needs a TCP load balancer.

Run the CA Job once, read the pin from its log and keep it:

```sh
kubectl apply -f namespace.yaml -f config.yaml -f storage.yaml
kubectl apply -f ca-init-job.yaml
kubectl -n jaunt wait --for=condition=complete job/jaunt-ca-init --timeout=120s
kubectl -n jaunt logs job/jaunt-ca-init
kubectl apply -f deployment.yaml -f service.yaml
```

Note: the Job leaves the age identity that decrypts the CA keys on the same volume (`ca/age-identity.txt`). That is acceptable for an evaluation only. For production, move it into a Secret, mount it, set `JAUNT_CA_KEY_FILE` to its path and delete the file from the volume. See [docs/security.md](../../docs/security.md).

The image reference is a placeholder. Build the image with `just image` from the repository and push it to your own registry; the project does not publish an image yet.
