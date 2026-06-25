# transparent-proxy

Transparent TCP proxy container: redirects outbound TCP to Gost, which forwards to an upstream HTTP proxy. Used with `network_mode: service:proxy-transparent` so apps need no proxy configuration.

## Image

- **GHCR:** `ghcr.io/singgihanggana/transparent-proxy:latest`
- **Production:** `docker pull ghcr.io/singgihanggana/transparent-proxy:latest`

## Domain-direct routing

The image can route selected domains directly from the proxy-transparent container while keeping all other traffic on the upstream proxy.

```text
app/flaresolverr in shared netns
  -> iptables REDIRECT
  -> embedded transparent router
      |- DIRECT_DOMAINS match -> direct socket connect
      `- default              -> UPSTREAM_PROXY
```

Configure with environment variables:

| Variable | Default | Meaning |
|---|---:|---|
| `REDIRECT_PORT` | `12345` | Local GOST transparent listener port |
| `UPSTREAM_PROXY` | `http://proxy:3128` | Default HTTP proxy for non-direct domains |
| `DIRECT_DOMAINS` | empty | Comma-separated exact/suffix domain rules to route direct |
| `ROUTER_PORT` | `3128` | Embedded router listener on `127.0.0.1` |
| `SO_MARK` | `100` | Packet mark used to bypass the iptables redirect loop |

Example for the manga stack:

```yaml
environment:
  - REDIRECT_PORT=12345
  - UPSTREAM_PROXY=http://proxy:3128
  - DIRECT_DOMAINS=comix.to,.comix.to,static.comix.top,.static.comix.top,mangadot.net,.mangadot.net
```

Rules beginning with `.` are suffix matches (`.comix.to` matches `api.comix.to`). `*.example.com` is normalized to `.example.com`.

If `DIRECT_DOMAINS` is empty, the container uses the original behavior and forwards all traffic directly to `UPSTREAM_PROXY` with no embedded router.

## Publish to GHCR

1. Push this repo to GitHub (`main`).
2. The workflow builds and pushes the image to `ghcr.io/<owner>/transparent-proxy:latest`. If the repo is under `singgihanggana`, the image is `ghcr.io/singgihanggana/transparent-proxy:latest`.
3. Or run **Actions → Build and Push to GHCR → Run workflow**.

## Local build

```bash
docker build -t ghcr.io/singgihanggana/transparent-proxy:domain-routing-test .
```

For production, prefer a pinned tag over `latest` once the staging test is green.
