<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-sigv4

First-party signed kind:auth plugin cdylib: the sigv4 auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `sigv4` | `busbar-auth-sigv4-plugin` | 1.6.0-dev.2 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-sigv4/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-sigv4/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-sigv4` is a `kind: auth` busbar plugin for AWS Signature Version 4, both ways:

- **outbound** (`auth: sigv4` on a provider): every request busbar sends is signed with SigV4
  (`Authorization`, `x-amz-date`, `x-amz-content-sha256`, and `x-amz-security-token` for a
  temporary credential), with the operator's own credential or, in passthrough, the caller's;
- **inbound**: a client request carrying an `AWS4-HMAC-SHA256` `Authorization` is verified against
  the busbar-issued `sigv4` credential its AccessKeyId names.

## Config

Configured under the `sigv4` module name. The style settings:

| key | required | meaning |
|---|---|---|
| `service` | yes | the AWS service the signature is scoped to (e.g. `bedrock`, `s3`); trimmed, 1 to 64 of `a-z`, `0-9`, `-` |
| `region` | yes | the AWS region (e.g. `us-east-1`); trimmed, 1 to 64 of `a-z`, `0-9`, `-` |
| `region_unread` | no | set by busbar, not by hand: the warning logged with each signature when the region was defaulted |
| `content_type` | no | read past (older configs carry it): the content type signed is the one the request is sent with |

`token_url`, `token_uri`, `scope` and `subject` (keys busbar forwards from its shared provider
schema) are ignored with one WARN at the bind. Any other key is refused by name. A `service` or
`region` that is not of the shape above is refused at open (`settings.service: ...`,
`settings.region: ...`), at `validate`, `open` and `refresh` alike.

### The credential

`ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]`. One that is not UTF-8, has no `:`, has an empty
access key id or secret, an empty session token, or an access key id or session token no header
value may carry, is refused at open (one `credential: ...` line per finding, never the
credential's bytes). No credential at all opens a passthrough-only binding: it signs only with a
caller's credential, and a request asked to sign with the operator's own fails (it is never sent
unsigned).

### What is signed

The method, the canonical URI, the canonical query, the content type the request is sent with,
`host`, every `x-amz-*` header the request is sent with, `x-amz-date`, `x-amz-content-sha256` (the
SHA-256 of the body) and, for a temporary credential, `x-amz-security-token`. The canonical URI is
the path normalized (`//` collapsed, `.` and `..` resolved) and encoded twice, except for `s3`,
whose path is encoded once and never normalized. The canonical query is each name and value
decoded and re-encoded (uppercase hex), sorted by name then value.

## Inbound verification

- No `authorization` line, or one that does not open with `AWS4-HMAC-SHA256`: not this plugin's
  credential (busbar tries its next path).
- Otherwise every failure is the one opaque 401, and the plugin's own log names the reason
  (`malformed`, `missing-date`, `expired`, `signed-headers`, `signature`, `credential-unavailable`,
  ...), never the signature, the secret or a token.
- The `Authorization` must parse; `x-amz-content-sha256` and `x-amz-date` must be present and
  signed; `host` must be signed (with no `host` line, as on HTTP/2, the request's authority is the
  host); `UNSIGNED-PAYLOAD` is refused; the body's SHA-256 must equal the signed
  `x-amz-content-sha256`; `x-amz-date` must be within 5 minutes of busbar's clock and match the
  credential scope's date.
- The signature is recomputed the AWS way (as above, the credential scope's service choosing the
  `s3` rule or not; a repeated signed header is all its values, comma-joined in order) with the
  secret busbar's `records.secret` answers for the AccessKeyId (kind `sigv4`), compared in constant
  time. An unknown AccessKeyId is checked against a fixed dummy secret in equal time. Only a
  verified signature over a live credential admits; the identity's subject is the AccessKeyId.

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
