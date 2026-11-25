# Service onion v3 (C tor, voir ADR-0006) devant le serveur de messagerie.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor \
 && rm -rf /var/lib/apt/lists/*
COPY torrc /etc/tor/torrc
# Les clés du service onion (= son adresse) vivent dans un volume dédié.
RUN mkdir -p /var/lib/tor/messagerie && chown -R debian-tor:debian-tor /var/lib/tor && chmod 700 /var/lib/tor/messagerie
USER debian-tor
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
