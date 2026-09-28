# Encrypt selected span attributes in the Alloy OTel engine

## Decision and boundary

Add a traces-only OpenTelemetry Collector processor named `encrypted_attributes` to the `alloy otel` distribution. It replaces each selected string-valued span attribute, such as `password="abc"`, with one string-valued span attribute, `enc.password=<authenticated ciphertext>`. It does not add `enc_eq`, alter Tempo, encrypt other attribute scopes, or register an `otelcol.processor.*` component in Alloy's Default Engine (`alloy run`). Operators must put the processor before any batch processor, exporter, or other consumer that could expose the original value. The [frozen wire contract and fixed vectors](#frozen-wire-contract-and-fixed-vectors) below govern bytes, names, and query interoperability; this document specifies the Alloy side.

This design belongs in `docs/developer/` because `docs/design/NNNN-...` requires a real proposal issue number; none is assigned here. The OTel-only scope needs a product decision before proposing a maintained bundled component: [Alloy's component inclusion guidance](add-otel-component.md) normally expects non-community components in both engines. Adding a Default Engine wrapper is not part of this change.

## Configuration and lifecycle

The OTel Collector requires `processors` to be a map; the `encrypted_attributes` entry contains an array of policies, not a top-level array. Each policy assigns disjoint span names to one key file. Use **random production keys**, never the public fixtures below:

```yaml
processors:
  encrypted_attributes:
    policies:
      - span_attributes: [password]
        key_file: /run/secrets/tempo-password-key
        value_scheme: aes256siv-hkdf-v1
      - span_attributes: [token]
        key_file: /run/secrets/tempo-token-key
        value_scheme: aes256siv-hkdf-v1

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [encrypted_attributes, batch]
      exporters: [otlphttp]
```

`Config` in `internal/static/traces/encryptedattributesprocessor/factory.go` has `Policies []Policy` with `mapstructure:"policies"`; each `Policy` has `SpanAttributes`, `KeyFile`, and `ValueScheme` with the corresponding `mapstructure` tags. Require a nonempty policy list and, for every policy, nonempty exact case-sensitive names, a key-file path, and `aes256siv-hkdf-v1`. Reject duplicate names **within or across policies** and names beginning with `enc.`. Do not trim or normalize attribute names or silently default the scheme. Scheme selection stays at encryptor construction; there is still one on-wire format.

`Config.Validate()` checks every policy without exposing secrets. `createTracesProcessor` reads and validates **every key file before constructing the processor**, failing startup on any read/decode/length error. Trim **only surrounding whitespace** from each file; accept padded or unpadded standard base64, reject interior whitespace and other encodings, and require exactly 32 decoded bytes. Derive each key and `kid` once, retain them in memory, and reload only on restart. Avoid returning/logging file contents, plaintext values, master keys or derived keys. Each selected name maps to its assigned encryptor. Rotated or concurrent key IDs can coexist in Tempo: browser equality compiles across loaded keys, but unknown-key histories cannot provide universal plaintext `!=` semantics.

Follow the local `servicegraphprocessor/factory.go` shape: `processor.NewFactory(component.MustNewType("encrypted_attributes"), createDefaultConfig, processor.WithTraces(createTracesProcessor, ...))`. Choose and document the Collector stability level at registration; do not claim GA by default. The factory creates only a traces processor, with a downstream `consumer.Traces`; it exposes no metrics or logs processor. `Start` need not open resources after successful construction; `Shutdown` must not promise secure erasure of Go strings or AES expanded state. Construction failures prevent pipeline startup, rather than making a partially configured processor.

## Frozen wire contract and fixed vectors

For a 32-byte master key, compute `kid` as the lowercase hex of the first 16 bytes of SHA-256(master). HKDF-SHA256 with IKM=master, UTF-8 salt `tempo-attr-v1`, UTF-8 info `aes-256-siv` yields 64 bytes. Use Go Tink `github.com/tink-crypto/tink-go/v2/daead/subtle.NewAESSIV` (RFC 5297 AES-256-SIV). The sole associated-data component for each attribute is `UTF8("tempo:span:v1") || 0x00 || uint32be(len(UTF8(storedName))) || UTF8(storedName)`; `storedName` includes the `enc.` prefix. Seal the original UTF-8 string bytes, including an empty string, with no nonce. The stored OTLP string is `enc:v1:<kid>:<unpadded-base64url(16-byte SIV || ciphertext)>`. Browser equality rewrites compare this **same stored field**; an alternate token or additional attribute would break the contract. Different stored names have different associated data and ciphertext.

The canonical fixed vectors use **public test-only** master bytes `00` through `1f` (standard base64 `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`), `kid` `630dcd2966c4336691125448bbb25b4f`, and derived 64-byte key hex `1bc2affe0fc67e9f1c1c597fe34bd9abab2644affb89d6af36b69fe2a1ca92cba01f1f436feac6ad9a1cb5896719b8afc6be509b6fcaa88bc7db9fcdfb41cf23`.

| Original name | Plaintext | Stored name | Exact stored string |
| --- | --- | --- | --- |
| `password` | `abc` | `enc.password` | `enc:v1:630dcd2966c4336691125448bbb25b4f:7aUwjY5fPtHvu_dUnzcxBJc6XQ` |
| `password` | empty string | `enc.password` | `enc:v1:630dcd2966c4336691125448bbb25b4f:l4ghA-S-aF9uZIBVXGBXsA` |
| `password` | `π🙂` | `enc.password` | `enc:v1:630dcd2966c4336691125448bbb25b4f:Q7TnRtl8MzhotH3OUlYfe4R-HKvCyg` |
| `token` | `abc` | `enc.token` | `enc:v1:630dcd2966c4336691125448bbb25b4f:Tmlsk4UeuIxW4e8k0i4OmCaSPg` |

The Go implementation must independently produce these exact bytes and interoperate with the browser implementation; do not recalculate and replace the contract vectors to fit an implementation.

## Trace consumption: batch preflight, then commit

`ConsumeTraces(ctx, td)` treats one incoming `ptrace.Traces` value as the atomic unit for local validation and mutation:

1. Traverse **all** resource attributes, instrumentation-scope attributes, span attributes, span-event attributes, and span-link attributes across every resource/spans group. Reject an attribute key beginning with the exact, case-sensitive `enc.` prefix at **any** of these scopes, even when its value is not selected or its span has no selected attributes. This reserves the namespace before Tempo's search metadata or Grafana's flattened display can confuse scopes. Other keys at these scopes remain untouched.
2. For span attributes only, find every configured exact original name that is present. If a selected value is not an OTLP string, fail the entire incoming batch; do not stringify, skip, or create an `enc.*` key. For each valid value, calculate its stored name and seal it with that name as AD. Stage the destination map, original name, stored name, and completed envelope in memory. Missing selected attributes are not errors, and an empty selected string must still be encrypted.
3. If **any** preflight or encryption step fails, return a non-secret error before mutating `td` or invoking the downstream consumer. If all succeed, delete each original selected span key and insert its one `enc.<original>` string key. Forward `td` to `nextConsumer.ConsumeTraces(ctx, td)` exactly once. Propagate downstream errors; they occur *after* commit and are not a promise to undo downstream effects. No selected plaintext key or second equality token reaches that consumer.

Do not mutate while traversing or encrypting: an invalid reserved key in a later event, a non-string value on a later span, or an encryption failure after earlier valid spans must leave the whole batch unchanged and unforwarded. Preflight guarantees that destinations do not already exist. Any key without the reserved prefix and outside the selected span list remains as received; notably, a `password` on a resource, event, link, or scope is **not** encrypted. Return an error rather than swallowing it as some existing processors do. Error messages may identify a failing attribute name/scope but must never print its value.

Report `consumer.Capabilities{MutatesData: true}` so Collector fanout can isolate data before this processor mutates it. This capability is necessary but not a substitute for the preflight transaction; it also does not undo plaintext exposure by an upstream processor or exporter. The initialized encryptor and selected-name lookup are read-only during concurrent `ConsumeTraces` calls; stage data per call, not in shared mutable processor state.

## Registration and file ownership

Implement the factory/configuration and processor in `internal/static/traces/encryptedattributesprocessor/factory.go` and `processor.go`, with focused tests alongside them. This package path is local to the Alloy Go module, not an upstream Collector Contrib package. Add under `processors:` in `collector/builder-config.yaml` an OCB entry using the existing local-module pattern:

```yaml
- gomod: github.com/grafana/alloy v1.19.0 # x-release-please-version
  import: github.com/grafana/alloy/internal/static/traces/encryptedattributesprocessor
  name: encrypted_attributes
```

The module version must track the manifest's Alloy version; the displayed `v1.19.0` is the version currently in that manifest. The OCB manifest is the source for `alloy otel` registration. `internal/static/traces/config.go` constructs a separate legacy trace-factory map, while `internal/component/all.go` registers Default Engine components; neither is the OCB registration path and neither changes in this scoped design. Integration owner regenerates `collector/components.go` and generated dependency files with `make generate-otel-collector-distro` **after** implementation and review; nobody hand-edits generated code or runs generation during the design phase.

After design approval, independent code-writing slices can be assigned as follows, with no simultaneous ownership of one file:

- **Factory/key doer (historical implementation split):** `factory.go`, `factory_test.go` and Go Tink dependency changes; implement per-policy validation and one-time key loading, HKDF/`kid`, scheme dispatch and Tink seal/envelope. The current constructor binds a `[]*encryptor` to policy names; the earlier single-encryptor constructor is obsolete.
- **Traversal doer:** Own `processor.go` and `processor_test.go`; consume the above encryptor API, build an immutable selected-name lookup, preflight every required scope, stage all transformed values, commit once, forward once, and declare mutation capability. Cover later-span/event/link failures, untouched input and no downstream call on error, empty values, and retained unrelated fields.
- **OCB integration owner:** Own only `collector/builder-config.yaml` for registration, then regenerate generated OCB files and their separate module dependencies once after accepted code. Compare the generated processor factory type to `encrypted_attributes` and exercise an actual `alloy otel` pipeline. This manifest edit is independent of the processor files and root module dependency changes; generated artifacts are a later integration boundary.

Give each code-writing doer an independent paired reviewer the frozen contract, this design, its changed files, and acceptance checks. The factory reviewer checks exact HKDF/AD/SIV bytes, key-file parsing, scheme validation, non-secret failures and lifecycle; the traversal reviewer checks all five attribute locations, late failure atomicity, absence of plaintext forwarding, concurrency and Collector capabilities; the integration reviewer checks OCB registration, generated provenance and an actual `alloy otel` configuration. Reviewers read code without editing or running formatters, linters, builds or project-wide tests; the integration owner resolves findings and runs final validation once.

## Acceptance and remaining decision

Focused processor tests establish deterministic repeatability, the four frozen vectors, different IDs for two simultaneously configured keys, duplicate-name rejection across policies, invalid later key preventing construction, reserved `enc.` and non-string failures leaving a multi-span batch unchanged, removal of selected originals, and downstream error propagation. A cross-language check compares Go bytes with the browser against the frozen vectors. An end-to-end `alloy otel` run must show Tempo holds `enc.password`, not `password`, while a query over the ciphertext matches. A browser with only one policy key must leave values under the other policy encrypted.

**Open product decision:** whether to keep this processor OTel-engine-only as scoped here or seek maintainer approval and a real proposal issue for a bundled two-engine component. The decision does not change the frozen encryption/query bytes; a future Default Engine component requires separate registration, configuration, documentation and review. There are no unresolved wire-format choices in this design.
