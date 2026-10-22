# tlsfuzzer against the Goose server

`scripts/test-tlsfuzzer.sh` runs tlsfuzzer's TLS 1.3 server scripts against
`test/tools/echo_server.goose`, which offers P-384 for them beside the default groups
(`TLS_GROUPS`). Run 2026-10-22 on the desktop (Ubuntu 26.04 in WSL2, OpenSSL 3.5.5),
goose-tls `fe7cb36` on `goose-server`, tlsfuzzer `5eebc44` and tlslite-ng `7e95ea1`
from source, without kyber-py (so tlsfuzzer offers no ML-KEM).

Every failure left is one of the expected ones below; none is a fault of the server's
within the plan's scope.

| Script | Pass | Fail | Why the failures are expected |
|---|---:|---:|---|
| conversation, hrr, ccs, multiple-ccs-messages | 18 | 0 | |
| finished | 42 | 0 | One run in three failed one probe: a Finished with 196,608 bytes of padding, whose `decode_error` the server sends after the first record, while tlsfuzzer still sends and doesn't expect it yet; passed alone twice |
| finished-plaintext, empty-alert, unencrypted-alert | 17 | 0 | |
| 0rtt-garbage | 10 | 1 | The probe expects a fallback to TLS 1.2 |
| invalid-ciphers, nociphers, keyshare-omitted, legacy-version | 70 | 0 | |
| keyupdate | 62 | 0 | |
| pkcs-signature | 8 | 0 | |
| rsa-signatures | 6 | 2 | `rsa_pss_rsae_sha384` and `_sha512` alone: the server signs with `rsa_pss_rsae_sha256` only (plan) |
| shuffled-extentions, large-number-of-extensions | 41 | 0 | |
| signature-algorithms | 99 | 3 | 32,715 signature schemes make a ClientHello over 64 KiB, the limit taken from rustls |
| symetric-ciphers | 72 | 30 | TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256, not offered (plan) |
| unrecognised-groups | 20 | 12 | FFDHE groups, not offered |
| version-negotiation | 8 | 194 | Fallbacks to TLS 1.2; the server is TLS 1.3 only |
| zero-content-type, zero-length-data, record-padding | 23 | 0 | |
| record-layer-limits | 68 | 0 | |
| connection-abort | 140 | 10 | "After NewSessionTicket": no tickets yet (step 5) |
| no-unknown-groups, with `--groups=0x001d,0x0017,0x0018` | 258 | 1 | tlsfuzzer without ML-KEM counts X25519MLKEM768 (0x11ec) as unknown; the server supports it |
| obsolete-curves, with `--relaxed` | 87 | 84 | The server refuses a key share for an obsolete group with `illegal_parameter`, as the strict mode expects, but treats an obsolete group listed only in supported_groups as unknown, as the relaxed mode does; no tlsfuzzer mode is that mix. And X448, not offered |
| ecdhe-curves | 21 | 12 | X448 and P-521, not offered; P-384's probes, invalid points included, pass |
| serverhello-random, `-n 40` | 128 | 128 | FFDHE, X448, and P-521, not offered |
| lengths, `-n 300`, the echo server | 302 | 0 | |

Not run: non-support (servers without TLS 1.3), post-handshake-auth,
certificate-request, certificate-compression and client-certificate-compression,
psk_ke, psk_dhe_ke, session-resumption, and count-tickets (tickets are step 5),
ffdhe-*, eddsa, mldsa, ecdsa-* (an ECDSA certificate run is still to do), minerva,
mlkem (needs kyber-py), and keyupdate-from-server (needs the server to start one).

## What tlsfuzzer found, and the fixes

All in `e7704f9`, and on the side of each RFC 8446 rule the peer follows:

- A Finished of the wrong length got `decrypt_error`, or `unexpected_message` when it
  overflowed the server's 64-byte buffer; now `decode_error` from its header.
- An empty alert record got `decode_error`; now `unexpected_message`.
- A second change_cipher_spec was accepted; now `unexpected_message`.
- A ClientHello whose legacy_version is below 0x0303 was served; now
  `protocol_version`.
- A key share for an obsolete group (section 4.2.7) was ignored or chosen for a
  HelloRetryRequest; now `illegal_parameter`, as OpenSSL refuses it.
- ClientHellos over 16 KiB were refused; the limit is now rustls's 64 KiB.
