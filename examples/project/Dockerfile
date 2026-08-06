# SYNTHETIC project Dockerfile for project-root scans.
# Do not build or run.

FROM registry.example.invalid/synthetic-runtime:1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

WORKDIR /app
COPY --chown=10001:10001 app/ /app/

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/synthetic-app", "healthcheck"]

ENTRYPOINT ["/app/synthetic-app"]
CMD ["serve"]
