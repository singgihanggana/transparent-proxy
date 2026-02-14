# transparent-proxy

Transparent TCP proxy container: redirects outbound TCP to Gost, which forwards to an upstream HTTP proxy. Used with `network_mode: service:proxy-transparent` so apps need no proxy configuration.

## Image

- **GHCR:** `ghcr.io/singgihanggana/transparent-proxy:latest`
- **Production:** `docker pull ghcr.io/singgihanggana/transparent-proxy:latest`

## Publish to GHCR

1. Push this repo (including `transparent-proxy/` and `.github/workflows/push-transparent-proxy.yml`) to GitHub (`main` or `master`).
2. The workflow builds and pushes the image to `ghcr.io/<owner>/transparent-proxy:latest`. If the repo is under `singgihanggana`, the image is `ghcr.io/singgihanggana/transparent-proxy:latest`.
3. Or run **Actions → Build and push transparent-proxy → Run workflow**.

## Local build (optional)

```bash
docker build -t ghcr.io/singgihanggana/transparent-proxy:latest ./transparent-proxy
docker push ghcr.io/singgihanggana/transparent-proxy:latest  # after docker login ghcr.io
```

## Production

In `compose-a.yml`, `proxy-transparent` uses:

```yaml
image: ghcr.io/singgihanggana/transparent-proxy:latest
```

No need to build on the server; `docker compose pull` will get the image from GHCR. For private packages, log in first:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```
