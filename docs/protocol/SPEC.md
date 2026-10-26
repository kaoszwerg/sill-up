# The Sill wire protocol, for a client written elsewhere

What a viewer that is not the iOS app (a Rust client for Windows, Linux and macOS, say) must do to
reach Sill for Mac: discovery, transport, framing, every message kind, the session, pairing and the
small rules both ends share. Extracted from `Sources/StreamProtocol` (the shared wire code), the iOS
client and the host as of main at 36e7212 (2026-10-26). Where this text and the code disagree, the
code wins, and `vectors.json` is the code's own output.

- **`vectors.json`**: test vectors computed by StreamProtocol itself (`Tests/checks/protocol-vectors`).
  Exact bytes for framing and the binary payloads, the exact JSON Swift writes for each payload,
  what Swift's decoder accepts and refuses (`decodeProbes`), the pairing cryptography with fixed
  keys, the pairing link, a signed kind 18, a certificate, and the small parsers. CI fails when the
  file and the code drift apart; `Tests/checks/protocol-vectors/run.sh --write` regenerates it.
  `crosscheck.py` recomputes the cryptography with Python's hashlib and openssl, so every value is
  reachable with standard libraries (in Rust: `sha2`, `hmac`, `pbkdf2`, `p256`, `base64`).
- **Interop target:** the Sill.app installed on the Mac, or, headless and without posting input to
  that Mac, `SillHost --synthetic --pairing` (CLAUDE.md, Build and run: run it with
  `SILL_TEST_LOOPBACK=1 SILL_TEST_SOFTWARE_ENCODER=1 SILL_TEST_NO_ROUTER=1 SILL_TEST_NO_SCREEN=1` and
  `SILL_TEST_REMOTE_DIR=<dir>`; it prints its pairing code and link). A synthetic host posts no input
  to the Mac; Sill.app does. Sill for Mac 0.5.1 (the public release) predates the clipboard (kind 32)
  and the keyframe request (kind 44): detect features as §9 says, never by version.

Conventions: integers in headers and binary payloads are big-endian; "fp" is a fingerprint, the
SHA-256 of a P-256 SubjectPublicKeyInfo (§3.2); `‖` is concatenation; base64url is RFC 4648 §5
without padding.

## 1. Compatibility rules (read first)

The first public builds froze a floor that every later Mac keeps serving (CLAUDE.md, Compatibility
floor). A client built to this document stays working as long as it follows these rules:

1. **Unknown kinds are skipped**, never an error: read the header, discard `payloadLength` bytes.
2. **Unknown JSON keys are ignored**, and every field marked optional may be absent. Never require a
   field the Mac might not send.
3. **No enums on the wire** except the few Swift ones listed in §6.1 (their shapes are frozen).
   Strings with unknown values are skipped or treated as the documented default.
4. **Feature detection, not versions**: a feature is there when its marker arrives (a kind 16 on the
   connection means settings; `WindowList.gestures ≥ 1`, `WindowList.clipboard ≥ 1`; a `p` in the TXT
   record means a TLS home door). `hostVersion` is nil from SillHost; never branch on it.
5. **Send only what the host said it takes** (kinds 28 and 32 above all). Kind 44 is safe to send to
   any host: older ones skip it.
6. **The device floor**: today every host serves every device version (`DeviceGate.minimumDeviceVersion`
   is "0"). A later Mac may raise it and refuse older versions with kind 22 `update`. A client with its
   own version line (a Rust client at 0.1) should send a `Hello.appVersion` at or above the iOS app's
   (0.5.1 today), or a floor meant for the iOS app would refuse it.

## 2. Discovery

- **Bonjour** service type `_sill._tcp`, domain `local.`. The instance name is the Mac's name (a clash
  makes "Mac (2)"). The port is the home door's.
- **TXT record:**
  - `p`: how the home door speaks. Absent: a **plain** door (plain TCP, development builds and the CLI
    without `--pairing` only; a release client should refuse it). `"0"`: TLS, any device (Require
    pairing off). `"1"`, or **any other value, an empty one, or a bare key**: TLS, paired devices only.
    Keys are case-insensitive (`p`, else `P`). Vectors: `pairing.txtDoor`.
  - `r`: the recognition tag (§7.6), which tells a saved Mac's row apart whatever its Bonjour name.
    Its absence says nothing.
- **Away from home**: the remote door, TCP port 7455 by default (`MacInfo.remotePort`), at the
  addresses kind 18 lists (Tailscale's MagicDNS name and IPv4, a LAN address, an address name with a
  router forward), or those a pairing link carries. Same TLS and the same protocol as the home door.
- Direct Wireless (AWDL) and the cable's own pairing are Apple-only; a desktop client uses the
  network rows and the remote door.

## 3. Transport

### 3.1 TCP

No Nagle (`TCP_NODELAY`). The iOS client marks its traffic as interactive video (Wi-Fi WMM "VI");
on Windows and Linux use DSCP CS4/AF41 where available, it is optional. The remote door's own
settings: keepalive after 5 s idle, every 2 s, 3 probes, a 10 s connect timeout per dial.

### 3.2 TLS

- **TLS 1.3 only**, mutual authentication, no session tickets, no resumption (a resumed session
  would skip the certificate, and a removed device could come back on an old ticket).
- **SNI**: always `"sill"` (the host ignores it; a real name would cross the network in clear).
- **ALPN**: exactly one, `sill/1` for a session or `sill-pair/1` for a pairing connection. A host
  offers both for good.
- **Certificates**: each side presents a self-signed certificate of its own **P-256** key.
  Nothing in the certificate but the key matters: no names, dates or chains are evaluated by either
  side. The Mac's is v3 without extensions, signed ecdsa-with-SHA256 (`certificate.derHex`); the
  client may build its own any way (rcgen is fine) as long as it is X.509 with a P-256 key.
- **The pin** is the peer key's fingerprint: SHA-256 of the DER SubjectPublicKeyInfo
  `SEQUENCE { SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 }, BIT STRING 00 ‖ 04 ‖ X ‖ Y }`
  (`keys.*.spkiDER`, `keys.*.fingerprint`). Compute it from the leaf exactly as received, without
  evaluating anything.
- **The client's verifier** (rustls: a custom `ServerCertVerifier`; also verify the TLS 1.3
  CertificateVerify signature with the leaf's key, using `p256` directly if a library refuses the
  extension-less certificate):
  - a saved Mac: accept only its pinned fp;
  - an unsaved Mac (a pairing connection, a session at a `p=0` door): accept any P-256 key, and
    take the fp from the session for pairing.
- **What the host does**: on `sill/1` it trusts the key only if it is paired, or if Require pairing
  is off at the home door. A refused key fails inside the handshake: the client may see the
  connection established, then an alert on its first read. On `sill-pair/1` it trusts any key.
- **The Mac ID** is Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) of the fp's first 10 bytes,
  most significant bits first, 16 characters (`keys.*.macID`). A client checks
  `macID == MacID(fp)` everywhere it is given one.

## 4. Framing

Every message, both ways, on both doors:

```
offset  size  field
0       1     kind (u8)
1       8     timestamp: IEEE 754 double, big-endian bit pattern, seconds since 1970 (sender's wall clock)
9       1     isKeyframe: 1 or 0 (only frames and their parameter sets set it)
10      4     payloadLength (u32)
14      n     payload
```

Caps: the host refuses a client message over 1 MiB (`maxClientPayload`; a pairing message over
4 KiB) and closes. A client should accept frames up to 32 MiB (`maxFramePayload`) and any other host
message up to 4 MiB (`maxOtherHostPayload`), and close on more: a header that announces more is not
Sill (an SSH banner parses as a 1.7 GB payload). Read the payload in pieces, and count every piece
as a sign of life (§5.4): a keyframe on a slow link takes seconds. Vectors: `framing.messages`.

## 5. The session

### 5.1 Kinds

H→D host to device, D→H device to host. "JSON" payloads are UTF-8 JSON (§6).

| Kind | Name | Dir | Payload | Notes |
|---|---|---|---|---|
| 0 | parameterSets | H→D | binary §8.1 | before every keyframe |
| 1 | frame | H→D | HEVC access unit, length-prefixed NALs | `isKeyframe` on keyframes |
| 2 | windowList | H→D | JSON `WindowList` | first message of a session; again when windows or the source change |
| 3 | thumbnail | H→D | `windowID u32 ‖ JPEG` | every second or two per window |
| 4 | appIcon | H→D | `len u16 ‖ bundleID UTF-8 ‖ PNG` | once per app |
| 5 | appList | H→D | JSON `[AppInfo]` | installed apps |
| 6 | selectSource | D→H | JSON `StreamSource` | what to stream |
| 7 | launchApp | D→H | JSON `LaunchApp` | its first window is then selected |
| 8 | input | D→H | JSON `InputEvent` | §8.3 |
| 9 | viewport | D→H | JSON `Viewport` | panel size, scale, fps |
| 10 | ping | D→H | 8 bytes, opaque to the host | the iOS client sends its monotonic clock as a double |
| 11 | pong | H→D | the ping's payload, unchanged | RTT |
| 12 | clientStats | D→H | JSON `ClientStats` | once a second (logged by the Mac) |
| 13 | tick | H→D | empty | ~every 30 ms while live; ignore |
| 14 | cursorShape | H→D | binary §8.2 | the Mac's cursor image |
| 15 | windowCommand | D→H | JSON `WindowCommand` | close, minimize, fullScreen |
| 16 | hostSettings | H→D | JSON `HostSettingsState` | after the window list; on change; replies to 17 |
| 17 | changeSettings | D→H | JSON `HostSettingsChange` | only the fields one control changed |
| 18 | macInfo | H→D | JSON `SignedMacInfo` | who the Mac is, signed (§7.5) |
| 19 | pairRequest | D→H | JSON `PairRequest` | the one message of a `sill-pair/1` connection |
| 20 | pairResult | H→D | JSON `PairResult` | the answer; then the host closes |
| 21 | pairingWanted | D→H | empty | "show your code", home door only, at most once per 30 s |
| 22 | goodbye | H→D | JSON `Goodbye` | why the host closes (§5.5) |
| 23 | hello | D→H | JSON `Hello` | the first message of every session connection |
| 24 | macMenu | H→D | JSON `MacMenu` | the streamed app's menus (§9) |
| 25 | pressMenuItem | D→H | JSON `PressMenuItem` | |
| 26 | macPointer | H→D | JSON `MacPointer` | the Mac's pointer while another source moves it |
| 27 | fetchMenu | D→H | JSON `FetchMenu` | without id: the subscription |
| 28 | gesture | D→H | JSON `TrackpadGesture` | only if `WindowList.gestures ≥ 1` |
| 32 | clipboard | both | JSON `Clipboard` | only if `WindowList.clipboard ≥ 1` |
| 44 | keyframeRequest | D→H | empty | the picture was interrupted (§8.1) |

29–31 and 33–43 are held by open work; never use a number not listed here.

### 5.2 Opening a session

1. TCP, then TLS with ALPN `sill/1` and the pin (§3.2).
2. **Send kind 23 `Hello` first**, before anything else, e.g.
   `{"appVersion":"0.1.0","build":"1","protocol":1,"device":"Windows PC (x86_64)"}`.
3. The host answers, in this order: kind 2 (window list), kind 16 (settings), kind 18 (from a host
   with an identity), kinds 4 (icons), kind 5 (app list), kind 14 (cursor shape), then thumbnails and,
   once a source streams, kind 0 and a keyframe. **The session counts as connected at its first
   window list**: with TLS 1.3 the handshake completes before the host has judged the key, so a
   refusal can still arrive.
4. After the first window list the client sends: kind 9 (its viewport), kind 27 `{"token":N}` if it
   shows the Mac's menus, kind 32 `{}` if it shares the clipboard and the host says `clipboard ≥ 1`,
   and kind 6 `{"desktop":{}}` when `active` is `none` (the iOS app does that by itself, at most every
   10 s, and waits 2 s after a watched window closed, unless the user picked something meanwhile).
5. From then on: ping every 0.25 s, client stats once a second, input as it happens.

### 5.3 What streams

- One source at a time, chosen by the device (kind 6): `none`, `desktop` (the Mac's main display) or
  `window(id)`. The host restarts its pipeline on a change; new parameter sets follow (§8.1).
- `Viewport` (kind 9): `width`, `height` (the client's panel, in its points), `scale` (nil: leave the
  Mac window alone; 1.0: fit the Mac window to the panel at 1:1 points; 1.5: a window two thirds the
  size, so text renders 1.5× larger), `fps` (the client's display rate: 60 or 120; nil means 60). The
  host runs the stream at the highest `fps` among its devices, capped by its settings. Send it again
  when the panel's size or the display's rate changes.

### 5.4 Liveness and keepalive

- The host sends kind 13 ticks every ~30 ms while a source is live or input arrived in the last 3 s
  (this keeps a device's Wi-Fi out of power save). Ignore them; they count as life.
- **The client's liveness**: no byte received for `max(6 s, 4 × the worst RTT of the last second)`:
  the connection is lost.
- **The host's**: a home client whose socket takes no frame for 4 s (none in its first 8 s) is
  evicted; a remote client silent for 8 s too. A client must keep reading its socket at all times,
  even when it drops frames itself.
- Pong RTT: send `ping` with an opaque 8-byte payload, match the pong by its payload.
- `ClientStats` (kind 12) once a second: `fps`, `frameAgeMs` (now − the frame's header timestamp,
  clocks assumed synced), `rttMs` (each that second's median, or −1 when the second had no sample),
  `device`, and optional `frameAgeMaxMs`, `rttMaxMs` (that second's worst, −1 for none).

### 5.5 Ending

Kind 22 `Goodbye` comes before the host closes. `reason` is always there:

| reason | meaning | reconnect by itself |
|---|---|---|
| `quit` | Sill quit on the Mac | yes, when it is listed again (wait ~3 s: Bonjour keeps the old record 1 s) |
| `removed` | the Mac removed this device | no; it must pair again |
| `remoteOff` | Remote Access was turned off | no |
| `internetOff` | internet access was turned off | no |
| `busy` | the remote door's session limit | later |
| `pairingRequired` | Require pairing went on while this unpaired device was connected | no; pair |
| `update` | this client's version is below the host's floor | no |
| anything else | a later reason | only if `reconnect` is true |

Show `message` when present (cleaned with SafeText, one line, at most 300 characters); `update`
always has one, plus `minimumVersion`.

## 6. JSON

### 6.1 Swift's encoding (the part a non-Swift client gets wrong)

- **Key order is not significant** (Swift's follows a per-process hash seed). `vectors.json` sorts keys.
- **Optionals that are nil are left out**, never `null`. The decoder accepts `null` too.
- **Numbers**: a `Double` field accepts `1280` as well as `1280.0`; an `Int` field accepts `60.0` but
  refuses `60.5`. Send integers as integers.
- **`Data`** fields (only `Clipboard.image`, reserved) are standard base64 with padding.
- **Enums with associated values** use Swift's synthesized form: an object with exactly one key, the
  case name, whose value is an object of the labelled values, unlabelled ones as `_0`. Payload-less
  cases are `{}`. This applies to `StreamSource` and `InputEvent` only:

  ```json
  {"none":{}}   {"desktop":{}}   {"window":{"_0":4242}}
  {"pointer":{"_0":"move","x":0.25,"y":0.75}}
  {"scroll":{"x":0.5,"y":0.5,"dx":0,"dy":0.0125}}
  {"scrollGesture":{"_0":"began","x":0.5,"y":0.5}}
  {"text":{"_0":"Grüße ✓\n"}}
  {"key":{"hidUsage":227,"down":true,"modifiers":1048576}}
  ```

  In serde: an externally tagged enum whose variants are structs, with `#[serde(rename = "_0")]` on
  the unnamed field. A bare string (`"desktop"`), a named field instead of `_0`, an unknown case or
  two keys in one object all fail the whole decode, and the host then drops the message silently
  (`decodeProbes`).
- Plain string enums: `PointerAction` (`move`, `leftDown`, `leftUp`, `rightDown`, `rightUp`),
  `ScrollPhase` (`began`, `ended`, `momentumBegan`, `momentumEnded`), `WindowCommand.action`
  (`close`, `minimize`, `fullScreen`).

### 6.2 Types

Field names are the JSON keys. `?` marks an optional field. Every shape is in `vectors.json`, section
`json`.

- **WindowList** `{macName, windows:[WindowInfo], active:StreamSource, launchID?, hostVersion?,
  protocol?, gestures?, clipboard?}`. `launchID` is random per host launch: two connections whose
  lists carry the same one reach the same running host. **WindowInfo** `{id:u32, title, appName,
  bundleID, width, height}` (points; order stable, first seen first). **AppInfo** `{name, bundleID}`.
- **LaunchApp** `{bundleID}`. **WindowCommand** `{id, action}`.
- **Viewport** `{width, height, scale?, localCursor?, fps?}`. **ClientStats** above (§5.4).
- **HostSettingsState** `{settings:StreamSettings, persistent, virtualDisplayAvailable,
  virtualDisplayNote?, softwareEncoder, stream?:RunningStream, answering?, away?:AwayQuality,
  link?:LinkReport}`.
  - **StreamSettings** `{maxFPS, bitrate (per 60 fps), captureScale (2 Retina, 1 Standard),
    prioritizeSpeed, virtualDisplay, directWireless?}`.
  - **RunningStream** `{width, height, fps, mbps, onVirtualDisplay}`.
  - **AwayQuality** `{homeBitrate, homeCaptureScale, awayBitrate, awayCaptureScale,
    thisConnectionAway, awayRunning}`.
  - **LinkReport** `{state ("behind" or "stalled"; anything else means fine), withheldPerSecond,
    bitrate, carriedKbps?, suggestedBitrate?, suggestedCaptureScale?}`.
- **HostSettingsChange** `{token?, maxFPS?, bitrate?, captureScale?, prioritizeSpeed?,
  virtualDisplay?, directWireless?}`: absolute values; the token strictly increasing per client
  process; the reply is a kind 16 to this client alone with `answering` = the token. The host takes
  only the Mac menu's values: `maxFPS` 60 or 120, `captureScale` 2 or 1, `bitrate` one of the presets
  (`constants.qualityPresets`: 4, 8, 15, 25, 40, 80, 150 Mbps); anything else is answered with the
  old value. Never send a field the host's state did not report (nil `directWireless`).
- **Hello** `{appVersion?, build?, protocol?, device?}`.
- **Goodbye** `{reason, message?, minimumVersion?, reconnect?}`.
- **MacPointer** `{x?, y?, inside?, seen?}`: draw the Mac's pointer at `(x, y)` (fractions of the
  frame) when `inside` is true; drop the report when `seen` (input messages the host had read on this
  connection) is below the number of kind 8 this client has sent on it.
- **TrackpadGesture** `{gesture, fingers?}`: `swipeUp` (Mission Control), `swipeDown` (App Exposé),
  `swipeLeft`, `swipeRight` (the next or previous Space), `pinch` (Apps), `spread` (Show Desktop).
- **Clipboard** `{text?, image?, stop?}`: any kind 32 from the client subscribes it; `text` (at most
  256 KB of UTF-8, the JSON at most 1 MiB) becomes the receiver's clipboard; `{"stop":true}` ends the
  subscription. At most 4 subscriptions or texts a second. Never send `image` (a later generation).
  The host never sends text marked concealed or transient (password managers).
- **MacMenu**, **MacMenuItem**, **FetchMenu**, **PressMenuItem**: §9.
- **SignedMacInfo**, **MacInfo**, **MacAddress**, **PairRequest**, **PairResult**: §7.

## 7. Pairing

### 7.1 When

| Door | TXT | What a client does |
|---|---|---|
| home, plain (no `p`) | development only | refuse, or dial plain TCP in a debug build |
| home, `p=0` | open | a session with any key works; pairing still lets it be recognised and reached from afar |
| home, `p=1` | paired only | a saved Mac: dial pinned. Otherwise ask (§7.2), then pair with the code |
| remote | always paired | only with a code or link from a window open on the Mac (§7.3) |

A pairing connection: TLS with ALPN `sill-pair/1`, accepting any P-256 key; exactly one kind 19
(at most 4 KiB, within 10 s), one kind 20 back, then the Mac closes it. No hello. Every request has
`v: 1`; the host answers any other `v` with `closed`.

### 7.2 The ask (home door only)

`{"v":1,"method":"ask","proof":"","name":"Windows PC","model":"x86_64"}`. The answers:

- `{"ok":false,"reason":"shown"}`: the Mac shows its pairing window with a code and a QR code now.
  The client asks for the 12 digits (or the link) and pairs on a **second** pairing connection (§7.3).
- `openOnMac`: the Mac did not open a window by itself (it is already showing one, or limits apply:
  three asks in 10 minutes, 10 minutes of quiet for a device after the Mac's Cancel or five wrong
  codes). The person chooses Pair iPhone or iPad… on the Mac.
- `locked`: the Mac is locked; unlock it and try again.
- `ok` without a proof and `method: "cable"` comes only for an ask with `cable: true` over the USB
  cable to an iPhone or iPad. A desktop client never sends `cable` and accepts no proof-less ok.
- `{"v":1,"method":"cancel","proof":"",…}` withdraws an ask the Mac answered `shown` (the person
  cancelled on the client); always answered `closed`.

### 7.3 The code and the link

Either side takes the other's fp from the TLS session, never from a message (a relay in the middle
must present its own key, so the proof binds the wrong fp and the Mac rejects it).

- **Typed code**: 12 ASCII digits, the last a Damm check digit over the first 11 (table
  `pairing.dammTable`; a valid code's running interim ends at 0). Strip spaces, hyphens and no-break
  spaces first; check locally, so a typo never costs one of the Mac's five tries
  (`pairing.codeChecks`). Key:

  `K = PBKDF2-HMAC-SHA256(password = the 12 digits as ASCII, salt = "sill-pair-v1" ‖ fp_mac, 600 000 rounds, 32 bytes)`

  (~0.1–0.2 s; run it off the UI thread). Method `"code"`.
- **Link / QR**: `sill://pair?v=1&m=<macID>&k=<fp_mac base64url>&s=<secret base64url>&n=<name>&p=<port>&a=<address>…`.
  Parse strictly (`PairLink.parse`, vectors in `pairLink`): `v` must be 1; `m`, `k` (32 bytes),
  `s` (16 bytes) and `p` (1–65535) exactly once each; `m == MacID(k)`; each `a` through the address
  parser (§10.3), at most 5 kept; `n` cleaned with SafeText, "Mac" when empty; unknown parameters
  ignored. Dial the addresses (the remote door) **pinned to `k`**, or the home door's rows. `K` is the
  16-byte secret itself. Method `"qr"`. Always confirm a link before using it: anyone can hand one over.
- **Proofs** (both paths):

  ```
  proof_D = HMAC-SHA256(K, "sill-pair-v1 device" ‖ 0x00 ‖ fp_device ‖ fp_mac)
  proof_M = HMAC-SHA256(K, "sill-pair-v1 mac"    ‖ 0x00 ‖ fp_mac    ‖ fp_device)
  ```

  Send `{"v":1,"method":"code"|"qr","proof":<base64url(proof_D)>,"name":…,"model":…}`
  (`pairing.requestCode`, `pairing.requestQR`).
- **Answers**: `ok` with `proof` (base64url proof_M), `macID`, `name`, `recognitionKey` (base64url,
  32 bytes) (`pairing.resultOK`). **Check proof_M in constant time and `macID == MacID(fp_mac)`
  before saving anything.** Refusals: `code` (wrong proof, `triesLeft`), `closed` (no window, or the
  door does not take this method), `expired`, `stopped` (five wrong tries), `busy` (`retryAfter`
  seconds). A reason not in `pairing.knownReasons` comes with a `message` to show as it is.
- The remote door takes `qr` and `code` only while a pairing window the Mac's user opened is up
  (5 minutes, single use, five tries); otherwise its handshake refuses every pairing connection.

### 7.4 What a client saves per Mac

Its Mac ID, fp (the pin), name, recognition key, and kind 18's newest `issuedAt` and `addresses`
(§7.5), plus the client's own P-256 key (once per install, in the OS's credential store: Windows
Credential Manager or DPAPI, macOS Keychain, Linux Secret Service). The client's key is its identity
to every Mac; losing it means pairing again everywhere.

### 7.5 Kind 18: who the Mac is

`{"info": base64(MacInfo JSON bytes), "key": base64(X9.63 point, 65 bytes), "sig": base64(DER
ECDSA P-256/SHA-256 over the info bytes)}`. Verify the signature over **the exact decoded bytes**
(never re-encode), require `point` to be P-256, decode the JSON, and require
`macID == MacID(SHA-256(SPKI(point)))`. A saved Mac's kind 18 must also come from its pinned fp and
have a newer `issuedAt` than the one saved; then take its `addresses`. ECDSA is randomized: verify,
never compare signatures (`macInfo`; `tamperedInfo` must fail). Keep the saved addresses when a kind
18 lists none (Remote Access off).

**MacInfo** `{v:1, macID, name, issuedAt, remoteAccess, remotePort, internet, addresses:[MacAddress]}`;
**MacAddress** `{host, port?, kind ("vpn", "lan", "internet"), via}` (nil `port`: `remotePort`). Dial
the addresses in order, a second apart (happy eyeballs), each TLS `sill/1` pinned.

### 7.6 The recognition tag

TXT `r` = base64url(`n ‖ HMAC-SHA256(recognitionKey, "sill-tag-v1" ‖ n)[0..6]`), `n` 6 random bytes
per registration, 16 characters (`pairing.recognitionTag`). A row whose tag matches a saved Mac's
key is that Mac whatever its Bonjour name: dial it pinned. It is a hint, never authentication
(replayable): the pin decides. A row whose tag matches nothing, under a saved Mac's name, may be that
Mac set up again with a new key: the pinned dial fails; treat it as an unpaired door and pair again.

## 8. Video, cursor and input

### 8.1 Video

- **HEVC** (H.265), real-time, **no B-frames**: decode order is display order, no reordering.
- **Kind 0** (`parameterSets`): `nalLen u8 ‖ count u8 ‖ (len u16 ‖ bytes)×count`, the sets VPS, SPS,
  PPS as VideoToolbox gives them, `nalLen` normally 4 (`binary.parameterSets`). The host sends them
  **before every keyframe**. When they differ from the last ones (another size or source), make the
  decoder anew.
- **Kind 1** (`frame`): one access unit, NALs each prefixed by its length in `nalLen` bytes (hvcC
  style, no start codes). A decoder that wants Annex B: replace each length prefix with
  `00 00 00 01`, and put VPS/SPS/PPS (each with a start code) in front of every keyframe. The header's
  `isKeyframe` marks IRAP frames; the timestamp is the host's wall clock at encode (frame age).
- **Keyframes** come when a device joins, when the stream restarts, every `fps × 4` encoded frames
  (no time limit: a still window sends none), after a delta the host dropped for this device, and on
  request. Until the first keyframe after a gap, drop deltas.
- **Kind 44** (`keyframeRequest`, empty): send it when the decoder fails or the picture was
  interrupted (the window was hidden, the GPU device reset), because a still window never sends a
  keyframe by itself. The iOS client's rule (`KeyframeRecovery`): one request per interruption; again
  only if no keyframe came within `max(4 s, 4 × the worst RTT)`, spacing doubling 4, 8, 16, then
  32 s; never two less than 2 s apart. The host answers at most one a second per connection and
  never restarts the stream for it; a host from before skips it.
- Sizes: up to the Mac's Retina resolution (3024×1964 on a 14-inch MacBook Pro, 6016×3384 for a 6K
  Desktop), 60 or 120 fps, 4–300 Mbit/s. Use the platform's hardware decoder (Media Foundation or
  D3D11VA on Windows, VA-API or Vulkan Video on Linux, VideoToolbox on macOS).
- Latency beats completeness: render the newest decoded frame, drop older ones, never queue.

### 8.2 The cursor

The Mac's cursor is never in the video; the client draws its own pointer:

- **Kind 14** (`cursorShape`): `hotX, hotY, width, height` as big-endian float32 (Mac points), then a
  PNG, usually at 2× (`binary.cursorShape`). Draw it at the pointer with its hotspot.
- The client's own pointer position is where its last pointer input put it. While the Mac (its own
  mouse) or another device moves the pointer, kind 26 says where (§6.2): show that, until this
  client sends input again.

### 8.3 Input (kind 8)

- **Coordinates** are fractions of the streamed frame, 0…1 across its width and height, whatever the
  client draws it at. The host maps them onto the source.
- **Pointer**: `move` (hover), `leftDown`/`leftUp`, `rightDown`/`rightUp`, each with `x, y`. Send a
  `move` to the click point before a down. A drag is down, moves, up.
- **Scroll**: `scroll {x, y, dx, dy}`, dx/dy fractions of the frame the content moves, natural
  direction (positive dy: the content moves down, as when a finger drags down). For trackpad-like
  scrolling wrap the deltas in `scrollGesture` `began` … `ended`, then optionally `momentumBegan` …
  deltas … `momentumEnded`, the client generating the decaying momentum itself. A mouse wheel notch:
  deltas without phases.
- **Keys**: `key {hidUsage, down, modifiers}`. `hidUsage` is the USB HID keyboard usage (page 7:
  `a` 0x04, Return 0x28, Esc 0x29, Space 0x2C, arrows 0x4F–0x52, left Control/Shift/Option/Command
  0xE0–0xE3, right 0xE4–0xE7). `modifiers` bits: shift 1<<17, control 1<<18, option 1<<19, command
  1<<20 (CGEventFlags positions). Send a shortcut as a keyboard does: each modifier's own key down
  (carrying the modifiers down so far), the key down and up carrying all of them, then each
  modifier's key up in reverse order carrying what is still held. A key's up carries only the
  modifiers still held. Never leave a modifier down: release every key the client holds when it
  loses focus or the session ends.
- **A PC keyboard** (Windows and Linux; a desktop client on macOS sends its own keys as they are),
  as remote desktop clients for the Mac map it, so Ctrl+C, Ctrl+V, Ctrl+S and Ctrl+Tab do on the Mac
  what they do on the PC:

  | PC key | Mac | HID usage sent | modifier bit |
  |---|---|---|---|
  | Ctrl (left, right) | ⌘ Command | 0xE3, 0xE7 | command 1<<20 |
  | Windows / Super (left, right) | ⌃ Control | 0xE0, 0xE4 | control 1<<18 |
  | Alt, AltGr | ⌥ Option | 0xE2, 0xE6 | option 1<<19 |
  | Shift | ⇧ Shift | 0xE1, 0xE5 | shift 1<<17 |

  Translate the physical key (scan code), not the layout's character, for `key`; send what the
  layout produces through `text`. AltGr-composed characters (`@`, `€` on a German layout) go as
  `text`, never as ⌥ chords. The OS's own shortcuts (Alt+Tab, the Windows key alone, Ctrl+Alt+Del)
  stay with the PC unless the client captures the keyboard while its window has focus.
- **Text**: `text "…"` types Unicode (an IME's committed text, emoji, dead-key results). `"\n"`,
  `"\t"` and `"\u0008"` arrive as Return, Tab and Backspace. Use `key` for keys that mean commands
  and `text` for what a text field should receive; never both for one keystroke.
- **Gestures** (kind 28): only to a host with `gestures ≥ 1`; one of the six names, with `fingers`.

## 9. Optional: the Mac's menus (kinds 24, 25, 27)

- Subscribe once per connection after the first window list: kind 27 `{"token":N}` (no id). The host
  then sends the top level (`MacMenu` with `version`, `app`, `bundleID`, `menus`), and again whenever
  it changes. Tokens are the client's, strictly increasing per connection.
- Opening a menu: kind 27 `{"version":V,"id":"2","title":"File","token":N}` with the title shown; the
  answer has `answering: N`, `menu`, `items`, `more`. Items: `id` (a path of child indexes from the
  menu bar, "2.9"), `title`, `separator`, `enabled` (nil = true), `mark` ("✓", "-"), `key` (the
  shortcut as the Mac draws it, display only), `submenu`.
- Choosing: kind 25 `{"version":V,"id":"2.0","title":"New","token":N}`; the answer has `pressed`.
- A `version` other than the host's, a title that no longer matches, or no subscription: answered at
  once with a `note` ("The menus changed…"), nothing read or pressed. `stale: true`: show every item
  disabled. Ask at most 20 a second, press at most 4.

## 10. Shared small rules

### 10.1 SafeText (`safeText`)

For any name the other side supplies (a Mac's name, a goodbye's message): whitespace of every kind
becomes one space; other control, format, surrogate, private-use and unassigned characters are
removed (bidirectional overrides, zero-width characters); runs of spaces collapse; ends trimmed; at
most 64 characters (grapheme clusters; 300 for messages). Empty: show something of your own.

### 10.2 Versions (`sillVersion`)

Trim, drop one leading `v`/`V`, keep the longest prefix of ASCII digits and dots without trailing
dots; it must start with a digit and have at most 8 parts of 1–9 digits. Compare part by part, a
missing part being 0 ("0.10" > "0.9", "0.4" == "v0.4.0"). Shown with at least two parts.

### 10.3 Addresses (`addressParser`)

Strict, because system resolvers read "1.2.3" as 1.2.0.3: trim the ends; any other whitespace,
control character or `%` zone refuses; `[v6]` or `[v6]:port`; a bare string with two or more colons
is an IPv6 address without a port ("fd7a::1:7455" is an address); IPv4 exactly four decimal octets
0–255 without leading zeros; names per RFC 1123 (not all-numeric); ports 1–65535; a `sill:` text is a
pairing link. IPv6 is shown compressed and lower case.

### 10.4 base64url (`base64URL`)

RFC 4648 §5 without padding; decoding refuses padding, the standard alphabet's `+` and `/`,
whitespace, and any text that does not re-encode to itself.

## 11. What the Mac does that a client cannot see

- One stream for every device: all connected devices see the same source; the last pick wins.
- The host raises the picked window in regular mode and activates its app on a click; with the
  virtual display on, picked windows move to a display of their own.
- A window Sill resized for a device goes back when it stops streaming.
- A device with Larger Picture, Pencil hover, the trackpad's three-finger gestures and the iPhone
  Duo's layouts are the iOS app's alone: nothing on the wire depends on them.
