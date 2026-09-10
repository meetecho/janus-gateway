# Janus Gateway Tools

This directory contains helper utilities for generating and maintaining Janus Gateway documentation.

## `generate_swagger.py`

`generate_swagger.py` inspects `src/janus.c` and produces an OpenAPI document that describes both the public `/janus` API and the administrative `/admin` API. The script can also serve the specification through an embedded Swagger UI for quick local exploration.

### Prerequisites

- Python 3.8 or later (uses the standard library only)

From the repository root, run the script with `python3 tools/generate_swagger.py`.

### Common workflows

- **Generate the specification file**
  ```bash
  python3 tools/generate_swagger.py
  ```
  Writes the rendered OpenAPI document to `docs/swagger.json`.

- **Print the specification to stdout**
  ```bash
  python3 tools/generate_swagger.py --stdout
  ```
  Useful for piping the output to other tooling.

- **Check whether `docs/swagger.json` is up to date**
  ```bash
  python3 tools/generate_swagger.py --check
  ```
  Exits with status `0` when the existing file matches the generated output, otherwise exits with `1`. Handy for CI jobs that enforce documentation freshness.

- **Serve the spec with Swagger UI**
  ```bash
  python3 tools/generate_swagger.py --serve
  ```
  Starts a local development server at `http://127.0.0.1:8000/` (configurable with `--host` and `--port`). The UI automatically fetches the freshly generated specification. Combine with `--no-write` to avoid touching `docs/swagger.json` during ad-hoc previews.

### Additional options

- `--source`: path to `janus.c` relative to the repository root (defaults to `src/janus.c`).
- `--output`: destination path for the generated OpenAPI document (defaults to `docs/swagger.json`).
- `--no-write`: skip writing the output file, typically paired with `--serve`.

Run `python3 tools/generate_swagger.py --help` to see the full list of supported flags.
