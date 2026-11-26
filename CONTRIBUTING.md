# Contributing

Contributions are **welcome** and will be fully **credited**.

## Etiquette

This project is open source, and as such, the maintainers give their free time to build and maintain the source code held within. They make the code freely available in the hope that it will be of use to other developers. It would be extremely unfair for them to suffer abuse or anger for their hard work.

Please be considerate towards maintainers when raising issues or presenting pull requests. Let's show the world that developers are civilized and selfless people.

It's the duty of the maintainer to ensure that all submissions to the project are of sufficient quality to benefit the project. Many developers have different skillsets, strengths, and weaknesses. Respect the maintainer's decision, and do not be upset or abusive if your submission is not used.

## Viability

When requesting or submitting new features, first consider whether it might be useful to others. Open source projects are used by many developers, who may have entirely different needs to your own. Think about whether or not your feature is likely to be used by other users of the project.
## Procedure

### Before Filing an Issue

- Search existing issues to avoid duplicates
- Check the [documentation](docs/introduction.md) to ensure it's not a usage question
- Provide a clear title and description
- Include the exact command you ran and its full output
- Specify your environment (OS, CPU or GPU, Rust version, plc-mint version)
- Never include private keys or `keys.json` contents

### Before Submitting a Pull Request

- **Discuss non-trivial changes first** by opening an issue
- **Fork the repository** and create a feature branch from `main`
- **Follow all requirements** listed below
- **Write tests** for your changes
- **Update documentation** if behavior changes
- **Run code style checks** with `cargo fmt` and `cargo clippy`
- **Ensure all tests pass** with `cargo test`
- **Write clear commit messages** that explain what and why

## Requirements

- **Formatted with rustfmt** - Run `cargo fmt` before committing, and keep `cargo clippy` free of new warnings.
- **Add tests** - Your patch won't be accepted if it doesn't have tests. Changes to signing, encoding or nonce handling need a test that checks the result against an independent implementation, the way the existing suites check against libsecp256k1 and `serde_ipld_dagcbor`.
- **Never weaken verification** - Every hit is rebuilt, re-hashed and re-verified before it is printed. A change that skips or shortens that step will not be accepted.
- **Document any change in behavior** - Make sure the `README.md` and the pages in `docs/` are kept up-to-date.
- **Consider our release cycle** - We follow [SemVer v2.0.0](https://semver.org/). Command flags, `keys.json`, job files and the stock JSON Lines format are public interfaces. Breaking them needs a major version.
- **One pull request per feature** - If you want to do more than one thing, send multiple pull requests.
- **Send coherent history** - Make sure each individual commit in your pull request is meaningful. If you had to make multiple intermediate commits while developing, please [squash them](https://www.git-scm.com/book/en/v2/Git-Tools-Rewriting-History#Changing-Multiple-Commit-Messages) before submitting.

## How Changes Land

`main` is protected. Every change arrives by pull request, and direct pushes are
blocked.

- **Merges are squash-only, and the PR title becomes the permanent commit
  message on `main`.** Write it as one descriptive line. Individual commit
  messages are preserved in the body.
- No approval is required, but review threads must be resolved.

## Running Tests

```bash
cargo test
```

The GPU kernel compiles as C++ for the CPU, so its tests run on any machine:

```bash
cargo test --features gpu-ref
```

The end-to-end test runs the real CLIs against a local PLC directory and PDS from [atp-testnet](https://github.com/socialdept/atp-testnet) (PLC on `:7100`, PDS on `:7102`):

```bash
cargo build --release
cd claim && bun install && bun run e2e.ts
```

See [Testing](docs/internals/testing.md) for what each suite covers.

## Code Style

This project uses the default rustfmt style. Run it and Clippy before submitting:

```bash
cargo fmt
cargo clippy --all-targets
```
