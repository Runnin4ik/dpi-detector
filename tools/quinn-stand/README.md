# `quinn-stand` — the QUIC library this repository does not use

An experiment, not part of the product. It answers one question with a
measurement instead of an argument: **what does a ready-made QUIC stack see on
the host list test 2 already covers?**

It is a standalone cargo project, not a workspace member (the empty `[workspace]`
table in `Cargo.toml` keeps it out): `quinn`'s default features pull
`rustls-ring`, and neither `quinn` nor `ring` may enter the root lock file or the
`policy` CI job's graph. Building it here also measures that cost, which is the
second thing the experiment is for.

What it does: for every host in `scripts/quic/hosts.txt`, connect over QUIC with
ALPN `h3`, an 8-second idle timeout (the value measured for the probe), and a
certificate verifier that accepts anything (the endpoint's chain is not the
subject). Then print the outcome in the vocabulary the column uses — a completed
handshake, a stateless reset, a close with a code, a transport error, a version
mismatch — plus `ConnectionStats` and the elapsed time.

The question that matters is not whether it connects. It is:

* does it classify the endpoints this probe gets wrong the same way, or better?
* and, decisively, **can it tell "a reply arrived that opens under no key" from
  "nothing arrived"?** That distinction is the probe's most valuable finding
  (`quic_answered_without_handshake`, and the decoy Initial behind it), and a
  stack that requires decryption before it reports anything may not be able to
  make it at all. `ConnectionStats` is printed for exactly this reason.

```
cargo run --release              # the whole list
cargo run --release -- host ...  # a subset
```

## What it found (2026-09-26, all 34 hosts)

**It connects where this probe does not.** `www.apkmirror.com`,
`www.facebook.com` and `www.instagram.com` complete the handshake in quinn
(1.1–3.1 s) while the hand-written probe reports
`quic_answered_without_handshake` or a stateless reset — a third independent
implementation on the same addresses, agreeing with the stock client and with
Chrome. `www.messenger.com` is the exception: quinn times out there too.

**Its close codes are the same numbers.** `x.com`, `gateway.discord.gg`,
`hub.docker.com`, `www.themoscowtimes.com` and `www.canva.com` give
`the cryptographic handshake failed: error 40` — 0x100 + 40 = 296, which is
exactly the probe's `quic_close_296`; `www.cdn77.com` gives `error 112` = 368,
the probe's `quic_close_368`. So the vocabulary maps one to one, and the earlier
worry that a library collapses everything into "handshake failed" was wrong:
quinn separates reset, timeout, version mismatch and a close with its code.

**It is *less* sensitive on five rows.** `aws.amazon.com`, `soundcloud.com`,
`vk.ru`, `www.currenttime.tv`, `www.svoboda.org` (and `www.coursera.org`) time
out in quinn where the probe sees a close (296/336) or an ICMP
`port unreachable` — and where a *forced* Chrome completes the handshake. quinn
does not surface ICMP, and it has no connection to read stats from once
`Connecting` fails, so the decoy an endpoint sends first is not observable there.

**The timing tells the story.** A clean handshake takes 1.05 s; the hosts whose
endpoint answers only a *retransmission* take 3.06 s. `www.apkmirror.com` is a
3.06 s host — the endpoint answers the second flight, which is why a client that
waits (quinn, aioquic) gets a ServerHello and this probe's own schedule did not.

**What it costs** (measured on the branch `quinn-probe`, where the same column is
also implemented through quinn behind a `quinn-probe` feature):

* the artifact grows from **4 215 296** to **5 072 384** bytes — **+857 088
  (+20 %)** — with `--release --target x86_64-pc-windows-msvc` and
  `-C target-feature=+crt-static`;
* `cargo tree --target all -e normal,build -i ring` puts **`ring` in the shipped
  graph**, both through `quinn-proto` and through the vendored `rustls`:
  `ring ← quinn-proto ← quinn ← dpi-core ← dpi-detector`. That is what the
  `policy` job checks, so the feature cannot be enabled in this repository —
  `ring` is assembly, and there is no MIPS target for it.

**What the branch proved anyway**: the column run through quinn reports
`QUIC OK` for `www.apkmirror.com` and `www.facebook.com` and
`QUIC CLOSED (296)` for `www.canva.com` — the rows the hand-written probe gets
wrong. So the target for the probe is now a measured one, and the next step is
the one that found the previous three defects: capture the stand's own hello
(`tp_dump.py --extensions`) and diff it against the probe's.
