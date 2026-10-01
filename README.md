# ict-utils

Utilities for Elmeg/Funkwerk/Teldat ICT phone branch exchanges, using Python 3.14.
The installable package lives in `src/ict_utils`.

```sh
uv sync
uv run phonebook --help
uv run lcr --help
uv run ict-controlcenter --help
```

Phonebook and LCR commands accept `-i IP`, `-u USER`, `-p PASSWORD`, and `-d`
for packet debugging. Phonebook supports `print`, `erase`, `upload FILE`, and
`download FILE`; LCR supports `erase`, `upload FILE`, and `download FILE`.
ControlCenter streams syslog messages and accepts `-i IP` and `-d`.

Phonebook CSV files use UTF-8 with a header; see [README.phonebook](README.phonebook)
for the fields. PBX protocol text uses Latin-1 to preserve single-byte fields;
LCR XML transfers preserve the original bytes. Hardware-free tests cover the
protocol, transfers, CSV files, CLI parsing, discovery, and syslog buffering.
Actual PBX interoperability still needs a check against the device.

```sh
make check  # pytest first, then Ruff lint/format and ty
make build  # runs all checks before building the wheel and source archive
```

For automatic style fixes:

```sh
uv run pytest
uv run ruff check --fix
uv run ruff format
uv run ty check
```
