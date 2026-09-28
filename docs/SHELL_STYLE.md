# Shell Scripting Guidelines

1. 100% Bash scripts with `set -Eeuo pipefail` and `IFS=$'\n\t'`.
2. Wrap pipelines against SIGPIPE (141): `(cmd 2>/dev/null || true) | head -n1`.
3. Support `-h` and `--help` for non-root users with exit code 0.
4. Quoted environment variables in `config.env`.
5. Deterministic waiting (`wait_for_port`) instead of arbitrary sleeps.
