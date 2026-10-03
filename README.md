<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-sigv4

First-party signed kind:auth plugin cdylib: the sigv4 auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `sigv4` | `busbar-auth-sigv4-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-sigv4/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-sigv4/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-sigv4` is a `kind: auth` busbar plugin.

## Config

Configured under the `sigv4` module name.

## Build

```bash
cargo build --release -p busbar-auth-sigv4-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
