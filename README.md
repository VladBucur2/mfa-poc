# mfa-poc: BoK proof of concept for two-factor authentication

A small Spring Boot application that demonstrates TOTP two-factor authentication the way
SecureDesk will implement it: a two-step login in which a correct password alone produces a
session with no authorities, Argon2id password storage, an encrypted TOTP secret, replay
prevention, lockout, single-use recovery codes, an administrator reset, and a JSON audit trail.

It is deliberately **not** part of SecureDesk. It is the prototype of control SC-01, built so
the TOTP service, the security configuration and the test cases can be moved into the
application once that exists.

**To run the laboratory, follow [LOCAL-RUNBOOK.md](LOCAL-RUNBOOK.md) from start to finish.**
Everything runs in Docker on one laptop; this README describes the project itself.

---

## What is in here

| Path | What it is |
|---|---|
| `service/TotpService.java` | RFC 6238 verification: HMAC-SHA1 from the JDK, RFC 4226 truncation, one-step window, replay check |
| `service/Base32.java` | RFC 4648 Base32, so the secret fits an `otpauth://` URI |
| `service/SecretCipher.java` | AES-256-GCM for the secret at rest |
| `service/AuthService.java` | Password check, enrolment, code check, lockout window, recovery codes, reset |
| `service/AuditLog.java` | One JSON line per security event, with a fixed field set |
| `config/SecurityConfig.java` | Argon2id encoder (19 MiB, t=2, p=1), deny-by-default rules, CSP |
| `web/AuthController.java` | The two-step flow: `/login`, then `/mfa` or `/enrol`, then authenticated |
| `web/HomeController.java` | Home page, admin page, administrator MFA reset |
| `src/test/...` | RFC 4226 and RFC 4648 test vectors, replay and window tests |
| `Dockerfile` | Two stages: build with tests, then a JRE-only image running as an unprivileged user |
| `docker-compose.yml` | The laboratory: `mysql`, `app`, `nginx`, plus tools, captures and a plaintext listener on demand |
| `compose.insecure-cookie.yml` | Override for one capture in test case 11 only |
| `deploy/local/nginx.conf` | TLS, security headers, per-IP rate limit (20/min, burst 10, answers 429), external port forwarding |
| `deploy/local/nginx-plain.conf` | The plaintext listener for test case 11 |
| `deploy/local/setup.sh`, `deploy/make-env.sh` | One-time setup: secrets, certificate, `client.env` |
| `deploy/local/capture.sh` | `tcpdump` inside an Nginx container's network namespace |
| `deploy/client-tests.sh` | Scripted test cases, CSRF-aware, plus code helpers |
| `tools/Dockerfile` | Small image with bash, curl, oathtool, openssl and tcpdump |
| `LOCAL-RUNBOOK.md` | Every step, from installing Docker to the evidence |

## Quick start without Docker

If you have JDK 21 and Maven, the `dev` profile runs the application on its own, with an
in-memory database and a built-in development key:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

In PowerShell, quote the argument: `"-Dspring-boot.run.profiles=dev"`.

Open `http://localhost:8080/login` and sign in as `admin` with the default password from
`application.properties`. That account has `mfaRequired`, so it goes straight to enrolment.
Add the secret to a generator, for example `oathtool --totp -b "<secret>"`, confirm the code,
note the recovery codes, and you are in. The `requester` account has no second factor, so the
one-factor and two-factor flows can be shown side by side.

The `dev` profile uses an in-memory database and a non-`Secure` cookie so it works over plain
HTTP on your own machine. Never use it for the lab or the assessment.

## How the two-step flow is built

There is no `formLogin()`. `POST /login` checks the password and puts the user's **id** in the
session, not an `Authentication`. The `SecurityContext` stays empty, so every protected URL
still rejects the session. Only a correct code at `POST /mfa` (or confirmed enrolment at
`POST /enrol`) creates the `Authentication`, and the session id is rotated with
`request.changeSessionId()` before it is saved. Test case 3 fails if this is ever simplified.

`TotpService.verify()` skips every time step at or below the last accepted one, which makes a
code single use instead of valid for its whole window. Unknown usernames are checked against a
dummy Argon2 hash made at startup, so timing does not reveal which accounts exist. Codes are
compared with `MessageDigest.isEqual`.

## The audit trail

`logs/audit.log`, one JSON object per line:

```json
{"ts":"2026-10-01T09:14:22.118Z","event":"LOGIN_PASSWORD","actor":"admin","outcome":"SUCCESS","src_ip":"10.0.0.20","session":"3f9a1c77b2d4"}
{"ts":"2026-10-01T09:14:31.902Z","event":"MFA_VERIFY","actor":"admin","outcome":"FAILURE","src_ip":"10.0.0.20","session":"3f9a1c77b2d4","failed_count":"1"}
```

| Event | When |
|---|---|
| `LOGIN_PASSWORD` | Password step, success or failure |
| `LOGIN_BLOCKED` | Correct password on a locked account |
| `LOGIN_COMPLETE` | Fully signed in, with `factors` 1 or 2 |
| `MFA_VERIFY` | Code step, with `method` totp or recovery_code, or `failed_count` |
| `MFA_RECOVERY_USED` | A recovery code was spent (`alert`) |
| `MFA_LOCKOUT` | Ten failures inside fifteen minutes |
| `MFA_ENROL_START`, `MFA_ENROL_CONFIRM` | Enrolment begun and confirmed |
| `MFA_RESET` | An administrator removed someone's factor (`alert`, with `target`) |

No secret, code, password or raw session id is ever written: the session field is the first
six bytes of a SHA-256 of the id. Behind Nginx, `src_ip` is taken from `X-Forwarded-For`, which the
application trusts only from proxies on private addresses such as the Nginx container. With
Docker Desktop, browser traffic arrives through its port forwarder, so for the browser that
address is the Docker gateway; for the `client` container it is the container's own address.

## Tests

```bash
docker compose run --rm test        # or, with a local JDK and Maven: mvn test
```

`TotpServiceTest` checks the implementation against the ten official test vectors of
RFC 4226 Appendix D, then covers replay, the window boundary and malformed input.
`Base32Test` checks the RFC 4648 vectors and round-trips random secrets.

## Known limits

Written down because they belong in the report, not hidden behind a demo:

- TOTP is phishable through a real-time relay; WebAuthn is the phishing-resistant answer.
- The encryption key comes from an environment variable, not a vault (that is PoC 6.4).
- Behind Nginx, the hop to the application is plain HTTP inside the private container
  network; SecureDesk's SR-04 asks for TLS there too.
- The progressive delay blocks a request thread; acceptable here, not in production.
- `ddl-auto=update` creates the schema; a real deployment uses versioned migrations.
- There is no password pepper yet; SecureDesk adds it as part of SC-02.
- Pin the Spring Boot version you actually build with, and record it in the SBoM.
