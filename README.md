# Blueprint Framework (BPFW)

Blueprint Framework (BPFW) Core is a local structural guard for Python projects.
It creates blueprint authority files, checks them against real code, protects the authority files, watches for drift during AI-assisted work, and can rebuild shard layout when needed.

## What BPFW Core provides

- `bpfw/blueprint.yaml` authority generation.
- Sharded authority files under `bpfw/blocks/`.
- Verification against discovered Python code.
- Drift reports for undeclared, missing, invalid, duplicate, or unsafe authority data.
- OS-level authority lock and unlock commands.
- Semi-real-time watch feedback for code and authority changes.
- Automatic safe shard synchronization before `bpfw verify` and `bpfw status`.
- Manual shard synchronization through `bpfw reshard` for recovery or explicit maintenance.

## What is not included in Core

BPFW Core does not ship interactive completion tools, planning tools, or external tool orchestration. The public surface is intentionally limited to authority, verification, locking, watching, and shard maintenance.

## Install editable

```bash
pip install -e .
```

## CLI

```bash
bpfw init
bpfw verify
bpfw status
bpfw lock
bpfw unlock
bpfw watch
bpfw reshard
```

## Project root resolution

When running BPFW against another project, point it to that project root:

```bash
bpfw verify --project-root /path/to/target-project
```

The target project may contain `bpfw/blueprint.yaml`. If it does not, run:

```bash
bpfw init --project-root /path/to/target-project
```

## Authority workflow

1. Run `bpfw init` to create `bpfw/blueprint.yaml` and initial shard files.
2. Fill or adjust authority fields in the blueprint shards.
3. Run `bpfw verify` to check declared authority against real code.
4. Run `bpfw lock` to protect authority files.
5. Run `bpfw watch` while using Codex, Claude, Cline, or similar coding tools.
6. Run `bpfw unlock` before intentional authority edits.
7. Use `bpfw reshard` only when automatic synchronization cannot safely fix shard layout.

## Notes

- Internal Python package path is `bpfw`.
- Distribution/package name is `blueprint-framework` and CLI command is `bpfw`.

## Shard synchronization

`bpfw verify` and `bpfw status` perform a non-interactive safe synchronization pass before reading authority data. This keeps shard placement aligned with the current blueprint data during normal work.

`bpfw reshard` remains available as an explicit recovery command for locked files, interrupted writes, large migrations, or cases where automatic synchronization is intentionally skipped.
