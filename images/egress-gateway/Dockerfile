# Skald build-worker egress gateway: squid with the measured deny-by-default rule
# (WORKPLAN-BUNDLES.md "Build sandbox and dependency network"; T5 gate F6 part 4). GENERATED
# by dev/worker-artifacts.py --write from dev/egress_gateway.py; checked by the same script.
# The configuration is not baked in: the launcher writes squid.conf per attempt
# (publisher.worker.GatewayConfig, held to egress_gateway.squid_conf).
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache squid
USER squid
CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
