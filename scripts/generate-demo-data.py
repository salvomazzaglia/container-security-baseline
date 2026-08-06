#!/usr/bin/env python3
"""Validate or recreate known synthetic example paths under examples/.

Never scans outside examples/, never invokes Docker, never uses the network.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"

SYNTHETIC_MARKERS = (
    "SYNTHETIC",
    "synthetic",
    "registry.example.invalid",
    "example.invalid",
)

# Known synthetic example paths relative to examples/
KNOWN_PATHS = (
    "compose/insecure-compose.yml",
    "compose/hardened-compose.yml",
    "compose/mixed-compose.yml",
    "compose/compose-with-anchors.yml",
    "compose/compose.json",
    "compose/README.md",
    "dockerfiles/Dockerfile.insecure",
    "dockerfiles/Dockerfile.hardened",
    "dockerfiles/Dockerfile.multistage",
    "dockerfiles/README.md",
    "project/compose.yml",
    "project/Dockerfile",
    "project/.dockerignore",
    "project/README.md",
)

INSECURE_COMPOSE = """\
# SYNTHETIC EXAMPLE — intentionally insecure for rule demonstration.
# All hosts, registries, secrets, and service names are fake.
# Do not run. Do not use in production.

services:
  synthetic-web:
    image: registry.example.invalid/synthetic-web:latest
    privileged: true
    pid: host
    network_mode: host
    user: "0:0"
    cap_add:
      - ALL
    security_opt:
      - seccomp:unconfined
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/etc
    ports:
      - "*:8080"
    environment:
      API_SECRET: SYNTHETIC_NOT_A_REAL_SECRET
      DATABASE_PASSWORD: SYNTHETIC_NOT_A_REAL_SECRET

  synthetic-api:
    image: registry.example.invalid/synthetic-api:latest
    privileged: true
    user: root
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:rw
      - /etc/passwd:/etc/passwd:rw
    ports:
      - "*:3000"
    environment:
      TOKEN: SYNTHETIC_NOT_A_REAL_SECRET
    logging:
      driver: json-file
"""

INSECURE_DOCKERFILE = """\
# SYNTHETIC EXAMPLE — intentionally insecure Dockerfile.
# Do not build or run. All names and secrets are fake.

FROM registry.example.invalid/synthetic-app:latest

ARG API_SECRET=SYNTHETIC_NOT_A_REAL_SECRET
ARG DATABASE_PASSWORD=SYNTHETIC_NOT_A_REAL_SECRET

USER root

RUN curl -fsSL https://example.invalid/install.sh | sh

COPY . .

RUN chmod 777 /app /tmp /var

WORKDIR /app

ENTRYPOINT /app/start.sh
"""

REGENERABLE = {
    "compose/insecure-compose.yml": INSECURE_COMPOSE,
    "dockerfiles/Dockerfile.insecure": INSECURE_DOCKERFILE,
}


def _is_under_examples(path: Path) -> bool:
    try:
        path.resolve().relative_to(EXAMPLES.resolve())
        return True
    except ValueError:
        return False


def _has_synthetic_marker(text: str) -> bool:
    return any(marker in text for marker in SYNTHETIC_MARKERS)


def main() -> int:
    if not EXAMPLES.is_dir():
        print(f"error: examples directory missing: {EXAMPLES}", file=sys.stderr)
        return 1

    missing: list[str] = []
    non_synthetic: list[str] = []
    regenerated: list[str] = []

    for rel in KNOWN_PATHS:
        path = EXAMPLES / rel
        if not _is_under_examples(path):
            print(f"error: path escapes examples/: {rel}", file=sys.stderr)
            return 1
        if not path.is_file():
            if rel in REGENERABLE:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(REGENERABLE[rel], encoding="utf-8", newline="\n")
                regenerated.append(rel)
                print(f"regenerated: {rel}")
            else:
                missing.append(rel)
            continue
        if path.suffix.lower() in {".yml", ".yaml", ".json"} or path.name.startswith("Dockerfile"):
            text = path.read_text(encoding="utf-8")
            if (
                not _has_synthetic_marker(text)
                and "SYNTHETIC" not in text.upper()
                and path.name != "README.md"
                and path.suffix != ".dockerignore"
            ):
                non_synthetic.append(rel)

    if missing:
        print("error: missing required example files:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        return 1
    if non_synthetic:
        print("error: example files missing synthetic markers:", file=sys.stderr)
        for item in non_synthetic:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print(f"OK: validated {len(KNOWN_PATHS)} known synthetic example path(s)")
    if regenerated:
        print(f"regenerated {len(regenerated)} missing file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
