# Agents

If you are an AI agent working in this repository, two files are your instructions:

1. [CLAUDE.md](CLAUDE.md) is the technical contract: conventions, the Stop-and-Ask Gate, required reading per subsystem, the commands. It applies to every agent, whatever the file's name says.
2. [CONTRIBUTING.md](CONTRIBUTING.md) is the process contract: what checks a change, how commits are written and signed off, who reviews what.

Three rules to carry even if you read nothing else:

- Run the gates before you report a change done: `make check-all`, `make test`, `make check-clippy`, and for user crates `make check-user` and `make test-user`. Report a failure with its output; do not describe it away.
- Never bypass a hook or signing (`--no-verify`, `--no-gpg-sign`). Never add telemetry.
- A commit you wrote carries a `Co-Authored-By:` trailer naming you, a `Staged files:` block listing exactly the files in it, and the `Signed-off-by:` line of the person you work for.
