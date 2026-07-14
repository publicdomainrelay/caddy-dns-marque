Marque module for Caddy
=======================

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It manages DNS records via [AT Protocol](https://atproto.com) PDS repo records using the `at.marque.dns` and `at.marque.domain` lexicons — part of the [Marque](https://marque.network) domain registrar.

Derived from [caddy-dns/cloudflare](https://github.com/caddy-dns/cloudflare) (Apache-2.0).

## Caddy module name

```
dns.providers.marque
```

## Prerequisites

- [Marque](https://marque.network) account with a registered domain
- An [ATProto app password](https://atproto.com/guides/app-passwords) for authentication

## Configuration

The module authenticates to your PDS using your ATProto handle (or DID) and an app password. DNS records are stored as `at.marque.dns` records in your PDS repo, keyed by domain name.

### Caddyfile Examples

Single line:

```Caddyfile
tls {
    dns marque {env.ATPROTO_HANDLE} {env.ATPROTO_APP_PASSWORD}
}
```

Block syntax:

```Caddyfile
tls {
    dns marque {
        handle {env.ATPROTO_HANDLE}
        app_password {env.ATPROTO_APP_PASSWORD}
    }
}
```

### JSON Example

```json
{
    "module": "acme",
    "challenges": {
        "dns": {
            "provider": {
                "name": "marque",
                "handle": "{env.ATPROTO_HANDLE}",
                "app_password": "{env.ATPROTO_APP_PASSWORD}"
            }
        }
    }
}
```

## How It Works

1. Caddy initiates ACME DNS challenge for your domain
2. The module authenticates to your ATProto PDS with your handle + app password
3. Reads the `at.marque.dns` record for your domain (rkey = FQDN)
4. Appends the `_acme-challenge` TXT record to the zone's records array
5. After verification, deletes the challenge record

Zone data is stored as ATProto repo records at `at://<did>/at.marque.dns/<domain>`.

## Troubleshooting

### Error: `domain not registered`

The `at.marque.domain` record must exist for your domain before DNS records can be managed. Register the domain through Marque first.

### Error: `atproto login failed`

Verify your handle and app password. Ensure the app password has repo write access for the `at.marque.dns` and `at.marque.domain` collections.

### Error: `timed out waiting for record to fully propagate`

Marque nameservers propagate quickly, but some resolvers may cache. Configure a custom resolver:

```Caddyfile
tls {
    dns marque {
        handle {env.ATPROTO_HANDLE}
        app_password {env.ATPROTO_APP_PASSWORD}
    }
    resolvers 1.1.1.1
}
```

## License

This is free and unencumbered software released into the public domain. See [LICENSE](LICENSE) (Unlicense).

This project is derived from [caddy-dns/cloudflare](https://github.com/caddy-dns/cloudflare) which is licensed under Apache-2.0.
