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
| `crosscheck.py` | The same, but every attempt is made **at the address the detector itself resolved** (read from its `--json`), so an anycast difference cannot be mistaken for a wrong verdict |
| `replay.py` | Replays the detector's own captured ClientHello on a fresh connection, once and then as a retransmission — the experiment that showed an edge answering the second flight and not the first |
| `decrypt.py` | Opens the QUIC Initial packets of a capture by hand (RFC 9001 §5.2/§5.4), with an RFC 9001 A.1 self-test; the tool that showed the endpoint's first reply opens under no key this connection can derive |
| `tp_dump.py` | Reassembles a real client's ClientHello out of a capture and prints its transport parameters — where the browser's numbers in `probe/quic.rs` come from |
| `bracket.py` | For the whole host list in one window: a stock client, then the detector **once for all hosts**, then the stock client again. A verdict that disagrees with the stock client *in the same window* is the question the other scripts answer. `JOBS = 8`: a 34-host sweep is about a minute |
| `variants.py` | A stock client with one property of the detector's hello at a time (zeroed flow control, 1200-byte datagrams): the experiment that showed Cloudflare closing a zero-limit client with `Error opening control stream` |
| `browser_check.py` | Drives a headless Chrome with QUIC forced for one origin and reports what the endpoint did with a **browser's** hello — the reference the column actually claims |
| `online_h3.py` | Answers the *other* question — would a browser ever use HTTP/3 here — from what the host advertises (`Alt-Svc`, and its HTTPS record through a third-party resolver) plus `http3check.net`, and writes `target/validation/online-h3.txt` |
| `hosts.txt` | The host list `crosscheck.py`, `bracket.py` and `online_h3.py` default to |

**Every QUIC verdict measured in this file before 2026-10-02 was taken with a
local `nfqws2` (zapret2) QUIC desync in front of the machine, so the readings of
*endpoint* behaviour among them are void — the "unopenable first reply" and the
"answer only on a repeat" are that desync's fake and its `repeats=3`, not the
edge. See "Correction, 2026-10-02" below before trusting a row.**

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

> **Correction, 2026-10-02:** every measurement below was taken with a local
> `nfqws2` (zapret2) QUIC desync running on the router —
> `--filter-udp=443 --filter-l7=quic --payload=quic_initial
> --lua-desync=fake:blob=quic_google:repeats=3`. The "1200-byte packet that opens
> under no key" of point 1 is that desync's fake, not the endpoint's answer, and
> the "endpoint answers only a repeat" of point 2 is the desync's `repeats=3`
> delaying the real reply. With the desync off the same host answers the **first**
> flight — see "Correction" below. Point 3 (the probe sent its flight once) still
> stands, and the probe's repeats are still what a real client does.

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

### Correction, 2026-10-02: the unopenable first reply is the local desync

Point 1 above was read as an endpoint behaviour for months. It is not: the machine
running the stand had a **zapret2 (`nfqws2`) QUIC desync** in front of it for
every one of those measurements —

```
--filter-udp=443 --filter-l7=quic --payload=quic_initial \
  --lua-desync=fake:blob=quic_google:repeats=3
```

— and the "1200-byte Initial-shaped packet that opens under no key" is that
desync's fake. Two captures of the same host, minutes apart, one variable
(`target/validation/quic-danbooru-vpn-off.pcapng` with the desync, ...-zapret-off
without):

| capture | client packets | packets from the endpoint | what they are |
|---|---|---|---|
| desync on | 8 (four flights) | **25** | pairs of identical unopenable Initials at 0.156/0.157 s (empty destination CID, 20-byte source CID, ~20-byte payload, padded to 1200), the readable handshake only at 4.833 s |
| desync off | 8 (four flights) | **0** | the host is blocked at the ISP: no answer at all |

And on a host the ISP does **not** block, with the desync off
(`target/validation/quic-shopify-zapret-off.pcapng`), the endpoint answers the
**first** flight: `decrypt.py` opens frames 3–6 under the client's destination CID
— `ACK`, `ACK`, `CRYPTO handshake_type=0x02` (ServerHello), `CRYPTO` — with DCID =
the client's source CID, exactly as RFC 9000 §7.2 requires. No unopenable packet
appears anywhere in that capture.

The per-host split that looked like a policy — `blog.cloudflare.com` answering at
0.0 s while `danbooru.donmai.us` needed three repeats, on the same 8.6.112.6 — was
the desync's **hostlist**: the fake is applied to the flows the config names, not
to all QUIC. The 4.7 s figure that the probe's window was widened for
(`MIN_WINDOW`) is that delay, not a property of any endpoint.

What this costs the stand: any measurement of *endpoint* behaviour taken with
`nfqws2` running is void — the detector's own intercept notice exists for exactly
this reason, and it was not read before these runs. `crosscheck.py`, `replay.py`
and `decrypt.py` are still the right instruments; they need the desync off.

### Where the delay comes from: the router's own WAN side, 2026-10-02

`tcpdump -i ppp0 'udp port 443'` on the router, with the probe running from the
LAN box, answers the last open question — whose silence the 4.7 s is. For
`danbooru.donmai.us` (`target/validation/router-wan.pcap`, our address
100.90.18.140, the edge 8.6.112.6):

| t | direction | what |
|---|---|---|
| 0.000–0.001 | out | **11 copies of the fake**, SNI `www.google.com`, all with the *same* DCID `78e79846bbf37984` |
| 0.001 | out | our own Initial, SNI `danbooru.donmai.us`, DCID `9a10528898e086bb` |
| 0.024 | in | the edge's answer to the fake (2 Initials, its own SCID) |
| 0.675, 2.011 | out | our repeats — **the edge answers nothing** |
| 4.686 | out | our fourth send |
| 4.711 | in | the readable handshake (a *different* SCID: a new connection for our DCID) |

Three facts follow, and they settle the question the stand had left open:

1. **The fake leaves the router with the flow's own 5-tuple** — that is the whole
   mechanism of the desync, and it is why the ICMP for a TTL-carrying fake lands
   on the client's socket.
2. **All copies of the fake carry one DCID** (the blob's), so `repeats=3` and
   `repeats=11` are the *same single connection* at the edge. Measured: the answer
   to the fake is 2 packets either way, and the delay is 4.7 s either way — the
   gate is a timeout, not a count.
3. **The gate is the edge, not the DPI.** Our real Initials *do* leave (0.001,
   0.675, 2.011) and are simply not answered for 4.7 s — so the provider's filter
   is not holding them. The same capture against `www.google.com` and
   `www.dw.com` (11 fakes sent in both cases, `router-wan-google.pcap`) shows the
   edge answering the **first** Initial at 0.026 s and 0.140 s: Google's and
   Akamai's stacks demux strictly by DCID and have no such gate. Cloudflare's
   edge keeps the tuple for the half-open connection the fake created. That
   connection's own timeout is what the delay is — and it is **not** 4.7 s: that
   number is where the *probe's* retransmit ladder happens to land. Three clients,
   three ladders, one gate:

   | client | Initials sent at | answer |
   |---|---|---|
   | the probe (`PTO_FIRST` 666 ms) | 0, 0.67, 2.01, 4.69 s | 4.7 s — the fourth send |
   | curl 8.22 `--http3-only` (ngtcp2) | 0, ~1, ~3 s | **3.5–3.7 s over eight runs** — the third send |
   | Chrome, forced QUIC | 0, 0.30, 0.91, 2.12 s | none: it closes itself at 4.004 s of silence, before its next retransmit (~4.3 s) |

   So the edge's state expires ~2.5–3.5 s after the fake, and what a client sees is
   its first retransmit that lands after that. The probe's ladder is too slow to
   see the earlier opening, Chrome's 4 s silence deadline is too early, curl's
   lands in between. Baselines in the same window: `blog.cloudflare.com` (no fake,
   same edge) answers curl in 0.16–0.27 s, `www.google.com` in 0.23 s.

`exclude.list` on that router holds `cloudflare.com`, which is why
`cloudflare.com` and `blog.cloudflare.com` — the same edge address as
`danbooru.donmai.us` — never receive the fake and never pay the delay: the
per-host split that looked like a policy was the router's own exclusion list.

Which edges gate, measured over the two host lists (the shipped defaults and
`hosts.txt`, one run each, the desync on with `repeats=11`; the AS is Team
Cymru's origin lookup, not a guess from the prefix):

| edge | hosts | QUIC column |
|---|---|---|
| **AS13335 Cloudflare** | `danbooru.donmai.us`, `meduza.io`, `www.linkedin.com`, `www.shopify.com`, `discord.com`, `media.discordapp.net`, `holod.media`, `nnmclub.to`, `x.com`, `hub.docker.com` | **4.7–4.8 s**, the answer on the fourth send |
| AS13335 Cloudflare | `www.canva.com` | 0.0 s — the edge answers the *fake's* connection's close to our Initial at once |
| AS13335 Cloudflare | `www.apkmirror.com` | 0.2 s in one run, 2.0 s in another (the flaky host above) |
| AS13335 Cloudflare, the `cloudflare.com` zone | `cloudflare.com`, `blog.`, `developers.`, `www.` | 0.0–0.3 s — the fake is not sent at all (the router's `exclude.list`) |
| AS15169 Google | `www.google.com`, `www.youtube.com`, `*.google.com`, `fonts.gstatic.com` | 0.1–0.3 s |
| AS16625 Akamai | `www.dw.com`, `www.intel.com` | 0.1–0.3 s |
| AS54113 Fastly | `www.bbc.com`, `www.cnn.com`, `www.euronews.com`, `www.reddit.com`, `www.spotify.com`, `www.twitch.tv` | 0.1–0.2 s |
| AS32934 Meta | `www.facebook.com`, `www.instagram.com`, `www.messenger.com` | 0.1–0.3 s |
| AS16509 Amazon | `amnezia.org`, `www.amazon.com` | 0.1 s |
| AS19679 Dropbox, AS9002 RETN, AS44386 Ozon, Yandex | `www.dropbox.com`, `www.bing.com`, `www.ozon.ru`, `ya.ru` | 0.0–0.7 s |

So the gate is Cloudflare's, and inside Cloudflare it is not uniform: `canva`
answers at once (with a close that belongs to the fake's connection — the same
tuple binding, a different reaction), and `apkmirror` answers early or late
depending on the run. Every other CDN in the sample answered our **first**
Initial. For hosts whose verdict is `DROP`/`CLOSED` the column carries no timing,
so their gate is only visible in a capture — `x.com` and `hub.docker.com` were
read that way (their answers come at 4.708 s and 4.813 s, after the fourth send,
and carry our SCID; the fake's answers carry the blob's empty one).

Where the split is *not*: five repeat runs of each host put `danbooru.donmai.us`,
`meduza.io`, `www.linkedin.com`, `www.shopify.com`, `holod.media` and `nnmclub.to`
at 4.7–4.8 s every time, and the two hosts sharing an address agree with each
other (`meduza.io` and `danbooru.donmai.us` on 8.47.69.6; `holod.media` and
`nnmclub.to` on 188.114.97.1). The `CLOSED` rows were timed by the run's own wall
clock instead (the QUIC column dominates it): `x.com`, `hub.docker.com`,
`stackoverflow.com` and `gateway.discord.gg` take 5.2–5.3 s, while `www.canva.com`
takes 2.6 s and the Amazon-fronted `aws.amazon.com` / `www.coursera.org` — both
`CLOSED` too — take 1.3–1.8 s, i.e. they answer immediately. So the split is
**per zone and stable**, not per run and not per client; what the zone's
difference *is* cannot be seen from the client side. Two reactions are on record:
silence until the fake's connection expires (then a new connection answers), and
an immediate close sent from the fake's own connection (`canva`). The blob's fixed
DCID is a candidate for the second one — every flow's fake claims the same
connection ID, so the edge's state for it is shared across our flows.

### Rewriting the desync, if the gate has to go

The gate is created by the fake itself, so `repeats` and `cutoff` cannot move it:
measured, 3 copies and 11 copies both gate for 4.7 s, because every copy carries the
blob's one DCID and the edge reads them as one connection. zapret2 has no QUIC blob
modifier either — `fake` takes `blob` and `tls_mod`, and `tls_mod` is the TLS
ClientHello's (`lua/zapret-antidpi.lua`) — so the fake's identity is the blob file
and nothing else. Three levers remain, in the order worth trying:

1. **Kill the fake before the edge, keep the bypass.** `badsum` is a standard `fake`
   argument (`--lua-desync=fake:blob=quic_google:repeats=11:badsum`), plumbed through
   `reconstruct_opts`: the L4 checksum is made invalid, so the edge's stack drops the
   packet and never creates the connection, while the DPI still reads it. Untested
   here, and it needs both halves checked — a WAN capture (the fake must leave with an
   invalid checksum) and a verdict (the host must still complete QUIC; otherwise the
   DPI was fooled by nothing). `:ip_ttl=N` / `:ip_autottl=-1,3-20` is the same idea
   through the IP header; autottl needs an incoming TTL already seen on that rule
   instance (`apply_fooling`: "cannot apply autottl because incoming ttl unknown"),
   which the first QUIC flow to a host has not, so pair it with a static TTL.
2. **Send the fake only where QUIC is blocked.** The fake is what unblocks a host —
   with the desync off `danbooru.donmai.us` gets no answer at all — and what costs the
   gated ones 4.7 s (`blog.cloudflare.com`, same edge, no fake: 0.0 s). The honest
   form of this is a host list built by measurement: run the detector with the host
   out of the desync and keep the fake only for the hosts that then fail. A CDN name
   is not the criterion — `danbooru.donmai.us` and `blog.cloudflare.com` are both
   Cloudflare and differ.
3. **A fake that creates no state.** RFC 9000 §14.1 requires a server to discard an
   Initial carried in a datagram smaller than 1200 bytes, so an *unpadded* fake should
   be dropped without a connection while its ClientHello stays visible to the DPI (the
   1200 bytes are a server rule, not a DPI rule). Needs a new blob — the shipped
   `quic_google` is a captured 1200-byte packet — and is untested: a DPI that ignores
   short Initials would make it useless.

### A browser cannot see the gate, only fail on it

Measured with Chrome (`--origin-to-force-quic-on=danbooru.donmai.us:443`, headless,
`--log-net-log`, the desync on): the session is created, Initials go out with PTO
retransmissions, the edge's two 1200-byte replies come back at the **Initial** level
and Chrome cannot decrypt them (`QUIC_SESSION_DROPPED_UNDECRYPTABLE_PACKET` — the
fake's connection's keys), and after **4.004 s** of no network activity Chrome closes
the session itself with `QUIC_NETWORK_IDLE_TIMEOUT` (25). The pool job then reports
`net_error = -356` (`ERR_QUIC_PROTOCOL_ERROR`) and the page fails.

Chrome loses by *when it sends*, not by the gate's length: its Initials went out at
0, 0.300, 0.910 and 2.115 s (PTO doubling), so its last one is still before the gate
opens (~2.5–3.5 s), and the next retransmit was not due until ~4.5 s — while the 4 s
of received silence expired at 4.004 s, half a second earlier. So Chrome never sent an
Initial after the gate lifted: a gated host is not loadable over QUIC by a browser at
all, not slowly but not at all. Without the flag the browser races h3 against h2 and
TCP wins in milliseconds, which is why a normal visit shows `h2` and no delay: the
browser hides the gate rather than paying it.

### Does the host support HTTP/3, independent of our network

`online_h3.py` (full output in `target/validation/online-h3.txt`) answers the
other question — would a browser ever use HTTP/3 here — from what the host
advertises: `Alt-Svc` on its HTTPS response, and its RFC 9460 HTTPS record through
a third-party resolver, with `http3check.net` corroborating. 17 of the 34 rows
advertise HTTP/3:

* **17 advertise it**: `amnezia.org`, `danbooru.donmai.us`, `discord.com`,
  `holod.media`, `media.discordapp.net`, `meduza.io`, `nnmclub.to`,
  `www.apkmirror.com`, `www.dw.com`, `www.euronews.com`, `www.facebook.com`,
  `www.google.com`, `www.instagram.com`, `www.intel.com`, `www.linkedin.com`,
  `www.messenger.com`, `www.youtube.com`.
* **17 advertise nothing**, and are what `quic_unsupported.txt` lists:
  `aws.amazon.com`, `browserleaks.com`, `gateway.discord.gg`, `hub.docker.com`,
  `protonvpn.com`, `shikimori.io`, `soundcloud.com`, `vk.ru`, `www.canva.com`,
  `www.cdn77.com`, `www.coursera.org`, `www.currenttime.tv`, `www.linuxserver.io`,
  `www.svoboda.org`, `www.themoscowtimes.com`, `www.torproject.org`, `x.com`.

`gateway.discord.gg`, `hub.docker.com` and `x.com` are the rows that used to be
counted as serving, and that reading was wrong: their endpoints answer a forced
QUIC handshake, but they advertise nothing — `alpn=h2` only, and `x.com` has no
HTTPS record at all — so no browser is ever told to use HTTP/3 there, which four
other checkers and a browser agree with. **Serving HTTP/3 when asked** and **a
browser discovering HTTP/3** are two different facts, and this column is about the
second: what the host tells a client, not what it would do if one insisted.

A third fact separates them further: a headless Chrome with QUIC *forced*
(`browser_check.py`) completes the handshake with five hosts that advertise no
HTTP/3 — `aws.amazon.com`, `soundcloud.com`, `vk.ru`, `www.currenttime.tv`,
`www.svoboda.org` — because forcing skips discovery. Their endpoints do speak
HTTP/3; they just never tell a browser to use it.

The detector ships this table's verdict as data: `quic_unsupported.txt` holds the
hosts that advertise no HTTP/3, and test 2 does not probe their QUIC
column at all — the cell prints a dash and the summary counts the column out of
the hosts that can answer it (`--legend` describes the badge, `README.md` the
file and the rule). Regenerating the list means re-running this script.

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
34-host sweep with no regression. The sweep agrees with the advertisement on
which hosts serve HTTP/3 — but a row that is not `quic_ok` is not thereby a host
that advertises none: `x.com` closes this probe with 296 in the same window above
and advertises nothing, because reading a close is a different fact from being
refused a handshake.

What is left is a lower class — `aws.amazon.com`, `soundcloud.com`,
`www.currenttime.tv`, `www.svoboda.org`, `www.coursera.org` — where a *forced*
Chrome completes the handshake while the probe reads a close (296/336). None of
them advertises HTTP/3, so no browser reaches them over QUIC at all: the forced
check bypasses discovery.


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

`crosscheck.py` and `bracket.py` compare against `aioquic`, which
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

## The row that looked like a defect, and was not: `www.whatsapp.com`

This row is worth keeping, because it is where a measurement lied and the probe
was right.

`crosscheck.py` and `bracket.py` agree — the detector drops the host, and so does
aioquic, before and after, at `31.13.72.52`. `browser_check.py` then reported that
"a real browser completed the HTTP/3 handshake", and that report was taken at face
value for a while: it looked as though the probe's hello were distinguishable from
a browser's. It was not. The old `report()` decided with
`any("Handshake" in line for line in server_frames)`, where `server_frames` was
every QUIC packet not from `192.168.*` — Chrome's own background QUIC to Google
included, and every other host Chrome opened in the same capture. The capture did
hold a busy HTTP/3 conversation with `109.194.137.78`
(`whatsapp-cdn-shv-01-arn2.fbcdn.net`); that connection simply was not
`www.whatsapp.com`.

Scoped to the host's own connection — the fix, which imports `tp_dump.py`'s
reassembly instead of parsing SNIs a second time — the same capture says:

```
the browser used 31.13.72.52:443 for www.whatsapp.com (connection DCID=70692190fe957555 from 192.168.1.110)
0 QUIC packets from 31.13.72.52 on this connection
www.whatsapp.com: a real browser did NOT complete the HTTP/3 handshake with 31.13.72.52
```

So the browser went to the address the probe used and got the same silence: the
`QUIC DROP` is what a browser would report, and the third-party testers that see
HTTP/3 for this name are on another network. That is a finding about the path, not
about the probe. The one address the probe did not try — `157.240.205.60`,
`dns.google`'s answer — is silent too.

What the row still argues for is a diagnosis aid rather than a fix: a verdict is
about one edge, so the column should print which address it belongs to. The
verdict itself needs no change.
