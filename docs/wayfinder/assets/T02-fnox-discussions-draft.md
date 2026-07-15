# Draft: fnox Discussions post (T02 / OQ1)

Post under Robert's account at <https://github.com/jdx/fnox/discussions/new>
(suggested category: Ideas — Q&A also fits).

---

**Title:** Interest in a direct-HTTP Vault/OpenBao provider, or a fnox-native
secrets-server protocol?

Hi jdx —

I'm building a small self-hosted secrets server in Rust for a nonprofit dev
team: single binary, single node, speaks the Vault KV v2 API. Because it's
Vault-compatible, fnox's existing Vault provider already works against it with
configuration only — so nothing here needs fnox changes. I'm asking about
direction before I build toward anything upstream-facing.

Two questions:

1. **Direct-HTTP Vault/OpenBao provider.** The Vault provider currently shells
   out to the `vault` binary, which is BUSL-licensed. Would a PR adding a
   direct-HTTP provider — talks KV v2 over HTTPS, works against Vault, OpenBao,
   and anything API-compatible, drops the binary dependency — be welcome? I saw
   #525 (openbao provider) and #568 (third-party provider precedent) and would
   build on whichever fits.

2. **fnox-native server protocol.** Longer-term: is a fnox-native protocol for
   a remote secrets server something you'd ever want in fnox, or do you prefer
   server integrations to stay behind the existing provider interface? No
   proposal attached — just checking whether a design discussion would be
   welcome before I write one.

If either answer is "not interested", that's genuinely fine — the
Vault-compat path works with zero upstream buy-in. I just don't want to build
toward an integration you don't want.

Thanks for fnox (and mise)!

---

## Posting checklist

1. Review/edit the text above.
2. Post at <https://github.com/jdx/fnox/discussions/new>, category Ideas.
3. Record the thread URL (and later, any reply) in T02's Resolution.
