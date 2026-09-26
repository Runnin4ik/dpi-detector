# The QUIC stand

The tools here validate test 2's QUIC column against implementations that are not
this repository's, and they exist because the column's verdicts are claims about
the network: a claim that an endpoint stayed silent is only worth something if
something else can be pointed at the same endpoint and made to talk.

Everything is Python 3 plus `aioquic` (`pip install aioquic`) — a pure-Python
RFC 9000/9001/9114 stack, so nothing here shares a line of code with the probe
under test.

| script | what it answers |
| --- | --- |
| `validate.py` | Do the column's verdicts agree with a stock HTTP/3 client? One attempt per host from `hosts.txt`, plus the host's own `Alt-Svc` over TCP |
| `crosscheck.py` | The same, but every attempt is made **at the address the detector itself resolved** (read from its `--json`), so an anycast difference cannot be mistaken for a wrong verdict |
| `bracket.py` | Stock client → detector → stock client, one host at a time, in one window: the only way to tell "the endpoint is silent" from "the endpoint answers other clients and not us" |
| `replay.py` | Replays the detector's own captured ClientHello on a fresh connection, once and then as a retransmission — the experiment that showed an edge answering the second flight and not the first |
| `decrypt.py` | Opens the QUIC Initial packets of a capture by hand (RFC 9001 §5.2/§5.4), with an RFC 9001 A.1 self-test; the tool that showed the endpoint's first reply opens under no key this connection can derive |
| `tp_dump.py` | Reassembles a real client's ClientHello out of a capture and prints its transport parameters — where the browser's numbers in `probe/quic.rs` come from |
| `bracket.py` | For the whole host list in one window: a stock client, then the detector **once for all hosts**, then the stock client again. A verdict that disagrees with the stock client *in the same window* is the question the other scripts answer. `JOBS = 8`: a 34-host sweep is about a minute |
| `variants.py` | A stock client with one property of the detector's hello at a time (zeroed flow control, 1200-byte datagrams): the experiment that showed Cloudflare closing a zero-limit client with `Error opening control stream` |
| `browser_check.py` | Drives a headless Chrome with QUIC forced for one origin and reports what the endpoint did with a **browser's** hello — the reference the column actually claims |
| `online_h3.py` | Two third-party testers (`intodns.ai`, `http3check.net`) answer the *other* question — does the host serve HTTP/3 at all, from networks that are not ours — and writes `target/validation/online-h3.txt` |
| `hosts.txt` | The host list the first two use |

## What the stand measured

Run against the 34 hosts `hosts.txt` held at the time (2026-09-26, Windows x86_64,
the shipped defaults), `crosscheck.py` agreed with the detector on **13 of 34**
rows. The disagreements were not noise:

* Seven hosts the column called `QUIC DROP` — `discord.com`, `meduza.io`,
  `www.linkedin.com`, `danbooru.donmai.us`, `holod.media`, `nnmclub.to`,
  `media.discordapp.net` — completed a full HTTP/3 handshake with the stock
  client **at the same address, seconds before and after the detector's own
  attempt**.
* `www.google.com` and `www.youtube.com` (`QUIC CLOSED`, transport error 10) and
  `www.facebook.com` / `www.instagram.com` (`QUIC CLOSED`, stateless reset)
  answered the stock client `HTTP/3 200`.

The cause was in the probe, not in the network:

1. The endpoint's answer to a **first** Initial is a 1200-byte packet that looks
   like an Initial (long header, a 20-byte source connection ID, a length field)
   and opens under **no** key the client can derive — `decrypt.py` and tshark
   agree on that, and the TTL and IP-ID of that packet match the endpoint's own
   answers, so it is the edge and not an injected forgery.
2. A stock client ignores it and repeats its Initial on a loss timeout; the
   endpoint then answers with a readable ServerHello. `replay.py` proved this
   with the detector's own hello bytes: the first flight produced only the
   unreadable packet, the retransmission produced `ACK` + `CRYPTO`.
3. The probe sent its flight once and waited, so it reported `QUIC DROP` for an
   endpoint that was answering every browser on the same address.

The fix is in `crates/dpi-core/src/probe/quic.rs`: the flight is repeated on a
loss timeout — RFC 9002 §6.2's first PTO (twice the 333 ms initial round-trip
estimate, doubling after that, the same schedule aioquic's `get_probe_timeout`
computes) — and a reply that arrives but opens under no key is reported as
`QUIC CLOSED` with `quic_unreadable_reply` rather than as silence. `QUIC_TIMEOUT`
defaults to 8 s for the same measured reason: the repeats leave at ~0.7, 2 and
4.7 s and the answer to one of them arrives later still, so a four-second window
cannot see it.

Re-measured with `bracket.py` in one window after the fixes:

```
meduza.io        stock HTTP/3 200  | detector quic_ok(quic_server_hello)   | stock HTTP/3 200
www.linkedin.com stock HTTP/3 200  | detector quic_ok(quic_server_hello)   | stock HTTP/3 200
cloudflare.com   stock HTTP/3 301  | detector quic_ok(quic_server_hello)   | stock HTTP/3 301
x.com            stock closed 296  | detector quic_closed(quic_close_296)  | stock closed 296
www.google.com   stock HTTP/3 200  | detector quic_ok(quic_server_hello)   | stock HTTP/3 200
www.facebook.com stock HTTP/3 302  | detector quic_closed(quic_stateless_reset) | stock HTTP/3 302
www.apkmirror.com stock HTTP/3 200 | detector quic_closed(quic_answered_without_handshake) | stock HTTP/3 200
```

The first five agree, including the transport error code on `x.com`. The last two
are the remaining class: the endpoint answers our hello and a minimal stock hello
differently, in the same window, and neither the transport parameters nor the
application settings explain it.

### Does the host support HTTP/3, independent of our network

Two third-party testers (`online_h3.py`, full output in
`target/validation/online-h3.txt`) answer the other question from networks that
are not ours, and they agree on 31 of 34 rows:

* **20 hosts announce or serve HTTP/3**: `amnezia.org`, `danbooru.donmai.us`,
  `discord.com`, `gateway.discord.gg`, `holod.media`, `hub.docker.com`,
  `media.discordapp.net`, `meduza.io`, `nnmclub.to`, `www.apkmirror.com`,
  `www.dw.com`, `www.euronews.com`, `www.facebook.com`, `www.google.com`,
  `www.instagram.com`, `www.intel.com`, `www.linkedin.com`, `www.messenger.com`,
  `www.youtube.com`, `x.com`.
* **14 do not**: `aws.amazon.com`, `browserleaks.com`, `protonvpn.com`,
  `shikimori.io`, `soundcloud.com`, `vk.ru`, `www.canva.com`, `www.cdn77.com`,
  `www.coursera.org`, `www.currenttime.tv`, `www.linuxserver.io`,
  `www.svoboda.org`, `www.themoscowtimes.com`, `www.torproject.org`.

The three rows where the testers disagree are the useful ones, because the
disagreement is the definition of the question: `gateway.discord.gg`,
`hub.docker.com` and `x.com` answer `intodns.ai`'s QUIC handshake (`quic=ok`)
while advertising nothing, so `http3check.net` — which requires an advertised
alternative service — says no. **Serving HTTP/3 when asked** and **a browser
discovering HTTP/3** are two different facts, and this column is about the first.

A third fact separates them further: a headless Chrome with QUIC *forced*
(`browser_check.py`) completes the handshake with five hosts the testers call
"no HTTP/3" — `aws.amazon.com`, `soundcloud.com`, `vk.ru`, `www.currenttime.tv`,
`www.svoboda.org` — because forcing skips discovery. Their endpoints do speak
HTTP/3; they just never tell a browser to use it.

## What the probe gets wrong, against a browser

With the browser reference measured per host, the rows where a browser (or the
stock client) succeeded and the probe did not were **thirteen**. **They are all
closed now**, and the fifth defect below is what closed them — not any of the
hello edits above:

| host | before | after |
|---|---|---|
| `www.apkmirror.com` | `quic_answered_without_handshake` (5 runs of 6) | `quic_ok` |
| `www.facebook.com` | `quic_stateless_reset` | `quic_ok` |
| `www.instagram.com` | `quic_stateless_reset` | `quic_ok` |
| `www.messenger.com` | `quic_stateless_reset` | `quic_ok` |
| `www.canva.com` | `quic_answered_without_handshake` | `quic_closed(quic_close_296)`, as the stock client reads it |

Measured after the fix: twelve runs out of twelve on those four hosts, and a full
34-host sweep with no regression. The sweep now agrees with both online testers
host by host: every row that is not `quic_ok` is one of the fourteen hosts they
call "no HTTP/3".

What is left is a lower class — `aws.amazon.com`, `soundcloud.com`,
`www.currenttime.tv`, `www.svoboda.org`, `www.coursera.org` — where a *forced*
Chrome completes the handshake while the probe reads a close (296/336). None of
them advertises HTTP/3, so no browser reaches them over QUIC at all; the forced
check bypasses discovery, and both testers call them "no HTTP/3" too.


The four hosts in that table were the ones where the *stock client* and a
browser both got through; the rest of the thirteen were the endpoints that
refuse a handshake at all (`296`/`336`/`368`), where the probe's close was
already the right verdict and only the reading of a short-header packet differed.
The fifth defect below is the cause of both.

### The fifth defect: the exchange ended too early

Found by reading a capture of the probe's own traffic against Meta, not by
another hello edit — and this is what closed all four hosts above.

`Verdict::absorb` returned "nothing better can arrive" for a **short-header
packet**, and the retransmit gate stopped repeating once *any* Initial had
arrived. Both are wrong against the measured endpoints:

* **Meta** (`www.instagram.com`, `www.facebook.com`, `www.messenger.com`) sends a
  short-header packet (88 bytes) *before* the readable Initial that carries its
  ServerHello. The probe stopped at the first and reported a stateless reset
  while the ServerHello was already on its way — in the capture it is the very
  next frame.
* **Cloudflare** (`www.apkmirror.com`) answers the first flight with a readable
  Initial carrying an acknowledgement and nothing else, and sends the ServerHello
  only to a **repeat** — which every real client sends on a loss timeout
  (RFC 9002 §6.2) and the probe stopped sending once it had "an answer".

Now a short-header packet is remembered but does not end the exchange, and the
flight keeps repeating until a handshake message, a close, a Retry or a version
negotiation arrives (`Verdict::settled`). A genuine stateless reset is still the
verdict when nothing better comes; the window just runs out first.


### The reference is a browser, not a stock client

Two caveats stay, and neither is a verdict:

* **A difference of observation is not a disagreement.** The probe can see more
  than the stock client — an ICMP `refused`, a readable `quic_close_336`, a
  ServerHello where a 4-second minimal client times out — and `crosscheck.py`
  counts that as a disagreement, which is why its "N of 34 rows agreeing"
  understates the agreement. It never means the probe was wrong.
* **Different anycast addresses** — `amnezia.org` and `www.intel.com` appeared
  here earlier and agree in one window; `bracket.py` is the check for it.

For the rows above, the differences still measured between this probe's hello and
a live Chrome's are: the missing `trust_anchors` (`0xca34` — which quinn does
without and works), the key share (1263 bytes against 1258) and the ECH body (282
against 218). Each is a small edit and a `bracket.py` run away; the tooling for
the comparison is `tp_dump.py --extensions` on a capture of both clients.

### Three defects the comparison against a live browser found

All three were in the probe's hello, and all three are now fixed:
* **The transport parameters were missing.** The probe sent only
  `initial_source_connection_id`, leaving every limit at the RFC's zero default;
  RFC 9114 §6.2.1 requires an HTTP/3 client to let the server open its control
  and QPACK streams. Measured on a stock client with the limits zeroed: Cloudflare
  closes with `Error opening control stream` (transport error 258, TLS alert 2)
  and Google answers nothing. The probe now sends the set a live Chrome sends
  (`tp_dump.py` read it out of a capture), which turned `www.google.com`,
  `www.youtube.com`, `amnezia.org`, `holod.media` and `www.intel.com` from
  `QUIC CLOSED`/`QUIC DROP` into `quic_ok`.
* **The application settings advertised `h2`.** The shape is the TCP one, where
  Chrome sends `h2`; over QUIC the same extension carries `h3` (a live Chrome's
  hello: `0003026833` in extension `0x44cd`, this probe's: `0003026832`). The
  QUIC hello now edits that body, and only for shapes that send the extension at
  all.
* **The TCP-only extensions.** A Chrome *TCP* hello sends `status_request`
  (0x0005) and the signed certificate timestamp (0x0012); its QUIC hello sends
  neither. The QUIC hello now drops both — and the drop had to be unconditional:
  `status_request` is a *typed* rustls extension, not one of the shape's raw
  entries, so gating the edit on "does the shape send it" left it on the wire
  (measured: the capture still showed `0x0005` after the gated version).

### The fourth defect: `signature_algorithms` over QUIC

Found the same way as the first three — a capture of each client and
`tp_dump.py --extensions` — after two leads were ruled out by measurement:

* **GREASE is not the trigger.** Ours carried GREASE everywhere (a cipher, two
  extensions, a group, a version) and neither working client carries any: a live
  Chrome's QUIC hello has none, and quinn's minimal 288-byte hello has none
  either. Removing it (`HelloVariant::NoGrease`, now applied by the QUIC hello)
  changed **nothing** on `www.apkmirror.com`, `www.facebook.com` or
  `www.instagram.com`. It stays because it is what a browser sends over QUIC, not
  because it fixed anything.
* **`signature_algorithms` is.** The shape is the TCP one, and Chrome's TCP hello
  sends eight algorithms where its QUIC hello sends nine:

  | | body |
  |---|---|
  | Chrome over TCP (this repo's shape) | `0010 0403 0804 0401 0503 0805 0501 0806 0601` |
  | Chrome over QUIC (measured) | `0012 0403 0804 0401 0503 0805 0501 0806 0601 0201` |
  | quinn (measured) | twenty bytes, same list |

  The missing value is `rsa_pkcs1_sha1` (`0201`) — useless in TLS 1.3, which is
  exactly why the TCP shape drops it and why a fingerprinting edge may notice its
  absence. The QUIC hello now adds it.

  **What this does not prove.** `www.apkmirror.com` is an *intermittent*
  endpoint: six single-host runs after the change gave `quic_ok` once and
  `quic_answered_without_handshake` five times, and the same host had produced a
  `quic_ok` before the change too. So the value is a real gap against both working
  clients — Chrome and quinn both send the twenty-byte body — but the effect on
  that host is **not established**, and a single `quic_ok` is not evidence of a
  fix. The deterministic target is Meta, below.

`www.facebook.com` and `www.instagram.com` still answer a short header (read as a
stateless reset) while the stock client gets `HTTP/3 302`, so Meta has a second
trigger, still unfound. The remaining measured differences against a Chrome hello
are `trust_anchors` (`0xca34`, which quinn does without and works), the key share
(1263 bytes against 1258), the ECH body (282 against 218) and the extension order.



### The reference is a browser, not a stock client

`validate.py`, `crosscheck.py` and `bracket.py` compare against `aioquic`, which
is the right tool for "does the endpoint answer at all" and the wrong one for
"does it answer the way it answers a browser": measured on `www.apkmirror.com`, a
Chrome hello (two 1258-byte Initials, split ClientHello) gets the unreadable
first packet **and then a readable ServerHello**, Handshake and `SETTINGS`, while
a stock client's single-datagram minimal hello gets `HTTP/3 200` — and this
probe's browser-shaped hello gets the unreadable packet and, in some runs,
`quic_ok` and in others an Initial carrying no CRYPTO. A verdict that disagrees
with `aioquic` is therefore a *question*, not a defect: `browser_check.py` is what
answers it.

Caveats the runs taught:
* **A stock client's 4-second window is not evidence of silence.** The scripts
  used `TIMEOUT = 4.0` while the probe's own measured window is 8 s
  (`QUIC_TIMEOUT` in `config.yml`): the endpoint's answer to a retransmitted
  Initial arrives after the first PTO, so a 4-second client gives up first. That
  is how `www.dw.com`, `www.euronews.com`, `www.intel.com` and `amnezia.org` read
  as "no answer" in one pass and `HTTP/3 200`/`403` in the next — a difference of
  the *client*, not of the path. The scripts now use the same 8 s.
* `closed 1 (Idle timeout)` is aioquic's **own** timeout, not a close by the
  endpoint; counting it as a close inflated the disagreements until the scripts
  were fixed. Some of the movement from 21 to 22 is that counting, not behaviour.
* **The extension order is not comparable between two captures.** The Chrome
  shapes set `permute_extensions` (Chrome shuffles its extension order per
  connection), so two of this probe's own hellos differ in order and neither is
  wrong — reading that difference as a defect costs an hour, as it did here.
  What *is* comparable between captures: which extensions are present, their
  bodies, and the cipher list.
* An endpoint's willingness to answer is not stable. A full 34-host sweep
  minutes after a good one returned `QUIC DROP` for every host *including* the
  ones a stock client had answered, and the stock client timed out on the same
  hosts in the same minutes. Only a comparison made **in one window**
  (`bracket.py`) can tell a wrong verdict from a network that stopped answering.

## The other half of the stand

* The UDP tap lives with the TCP one: `tools/fingerprint/utls/lab` —
  `lab --quic-tap-port 443 --quic-upstream discord.com:443` relays every datagram
  to a real host and prints its size, direction and readable header. Point the
  probe at it and the question "did the endpoint answer at all" stops being a
  guess.
* `cargo run -p dpi-core --example quic_probe_once -- 127.0.0.1 <fingerprint>` is
  the client that can be pointed at that tap: the detector's own CLI classifies
  `127.0.0.1` as a local address and never probes it.
* Captures come from `dumpcap`/`tshark` (`-f 'udp port 443'`, then
  `-Y quic -T fields -e udp.payload`), which also decrypts Initial packets
  itself — an independent second opinion on every packet `decrypt.py` reports.

## The 69-host re-run (2026-09-26, after the repeated-flight fix)

`hosts.txt` was extended with 35 hosts — three Cloudflare names, five Google
ones, Meta, Microsoft, Apple, Amazon, Netflix, Twitch, Spotify, Reddit,
DuckDuckGo, Stack Overflow, BBC, CNN, Slack, Zoom, Dropbox, Shopify, the New
York Times, four Yandex/RU names and the three Telegram hosts — and the stand
re-run over the whole list, with `online_h3.py` asking the third-party testers
about the new ones in the same window.

* Agreement at the detector's own addresses: **60 of 69**, of which **27 of the
  original 34** — the 13-of-34 run above is the pre-fix number for those same
  hosts, so the repeated flight is what moved it.
* **33 of the 35 new hosts** agree, and 34 in substance. `www.dropbox.com` is a
  `?` only because `verdict()` has no bucket for "handshake ok, no response":
  both stacks completed the handshake. `mail.google.com` is the one row where
  the column is the more informative side — it reports
  `quic_closed(quic_close_0)`, a NO_ERROR close, where aioquic timed out and
  both testers said "unknown".
* Eight of the nine non-agreements run one way: the column obtained a reply, a
  close or an ICMP refusal where aioquic, pointed at the same address, saw
  silence. That is what a browser-shaped hello buys, and the reason the column
  exists.
* The close codes match the stock client's alert numbers exactly:
  `quic_close_336` ↔ TLS alert 80 (`www.microsoft.com`, `www.apple.com`,
  `www.svoboda.org`, `www.currenttime.tv`), `quic_close_296` ↔ alert 40 (`x.com`,
  `stackoverflow.com`, `www.themoscowtimes.com`, `gateway.discord.gg`,
  `hub.docker.com`, `www.canva.com`), `quic_close_368` ↔ alert 112
  (`www.cdn77.com`).
* Three rows the third-party testers make worth naming: `www.whatsapp.com` —
  one tester reports HTTP/3 while **both** local clients are silent, the row to
  look at when the question is a path block rather than a missing service;
  `ya.ru` — the reverse, the column gets a `Retry` and aioquic an `HTTP/3 302`
  while both testers say "no", so Yandex serves H3 only from this region;
  `www.netflix.com`, `duckduckgo.com`, `mail.ru`, `lenta.ru`, `ria.ru` and the
  three Telegram hosts drop here *and* serve no HTTP/3 anywhere, so their
  `QUIC DROP` is not a finding.

## The defect that is not in the hello: the address

`www.whatsapp.com` is the row that shows it. `crosscheck.py` and `bracket.py`
agree — the detector drops it and so does aioquic, before and after, at
`31.13.72.52`, the address the system resolver returns. `browser_check.py`
reported that a browser completed HTTP/3, and the capture says which address it
used:

| client | address | result |
| --- | --- | --- |
| detector, aioquic, Chrome (one attempt each) | `31.13.72.52`, the system resolver's answer | silence |
| aioquic, and the detector's own hello | `157.240.205.60`, `dns.google`'s answer — `whatsapp-cdn-shv-01-hel3.fbcdn.net` | silence (the example prints `elapsed: 8.02s`) |
| Chrome | `109.194.137.78` — `whatsapp-cdn-shv-01-arn2.fbcdn.net`, a Russian address | `HTTP/3 404` (aioquic); the detector's hello was answered in 0.01 s |

The hello is not the difference: at the working edge the detector's own hello is
answered as aioquic's is, and at the other two both are silent. The resolver is.
Following the RFC 9460 record does not help either — the local resolver answers
`mmx-ds.cdn.whatsapp.net`, that record's target, with the same silent
`31.13.72.52` — so the fix is not "use DoH", it is "try the answers a browser
would", which is more than the one the system resolver happens to hold.

Two things to fix before the next run trusts `browser_check.py`:

* `report()` decides with `any("Handshake" in line for line in server_frames)`,
  and `server_frames` is every QUIC packet not from `192.168.*` — Chrome's own
  background QUIC to Google, and the host's own NATed outbound packets included.
  The verdict has to be scoped to the connection whose ClientHello carried the
  host's SNI (the DCID `tp_dump.py` already finds), and it should print the
  address the browser used: that field is what took three passes to notice here.
* A `QUIC DROP` for a host that serves HTTP/3 from another address is not a
  censored path, it is a verdict about one edge. The column should say which
  address its verdict belongs to.
