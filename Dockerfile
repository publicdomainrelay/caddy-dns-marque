FROM caddy:2-builder AS builder

ADD . .

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest && \
    xcaddy build \
    --output /usr/bin/caddy \
    --with "github.com/publicdomainrelay/caddy-dns-marque=."

FROM alpine:3.22

RUN apk add --no-cache \
    ca-certificates \
    libcap \
    mailcap

RUN set -eux; \
    mkdir -p \
        /config/caddy \
        /data/caddy \
        /etc/caddy \
        /usr/share/caddy \
    ; \
    wget -O /etc/caddy/Caddyfile "https://github.com/caddyserver/dist/raw/33ae08ff08d168572df2956ed14fbc4949880d94/config/Caddyfile"; \
    wget -O /usr/share/caddy/index.html "https://github.com/caddyserver/dist/raw/33ae08ff08d168572df2956ed14fbc4949880d94/welcome/index.html"

ENV XDG_CONFIG_HOME=/config
ENV XDG_DATA_HOME=/data

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

RUN setcap cap_net_bind_service=+ep /usr/bin/caddy; \
    chmod +x /usr/bin/caddy; \
    caddy version

LABEL org.opencontainers.image.title="Caddy with Marque ATProto DNS module"
LABEL org.opencontainers.image.description="Caddy web server image with the caddy-dns/marque DNS provider module baked in — manages DNS via ATProto PDS records"
LABEL org.opencontainers.image.url=https://github.com/publicdomainrelay/caddy-dns-marque
LABEL org.opencontainers.image.documentation=https://github.com/publicdomainrelay/caddy-dns-marque
LABEL org.opencontainers.image.licenses=Unlicense
LABEL org.opencontainers.image.source="https://github.com/publicdomainrelay/caddy-dns-marque"

EXPOSE 80
EXPOSE 443
EXPOSE 443/udp
EXPOSE 2019

WORKDIR /srv

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
