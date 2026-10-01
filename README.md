# mfa-poc — BoK proof of concept: two-factor authentication

A small Spring Boot application that demonstrates TOTP two-factor authentication the way
SecureDesk will implement it: a two-step login where a correct password alone produces a
session with no authorities, Argon2id password storage, an encrypted TOTP secret, replay
prevention, lockout, single-use recovery codes and a JSON audit trail.

It is deliberately **not** part of SecureDesk. It is the prototype of control SC-01, built so
the TOTP service, the security configuration and the test cases can be lifted into the
application once that exists.

---

## 1. What is in here

| Path | What it is |
|---|---|
| `service/TotpService.java` | RFC 6238 verification: HMAC-SHA1 from the JDK, RFC 4226 truncation, ±1 step window, replay check |
| `service/Base32.java` | RFC 4648 Base32, so the secret can go into an `otpauth://` URI |
| `service/SecretCipher.java` | AES-256-GCM for the secret at rest |
| `service/AuthService.java` | Password verification, enrolment, code verification, lockout, recovery codes |
| `service/AuditLog.java` | One JSON line per security event, with a fixed field set |
| `config/SecurityConfig.java` | Argon2id encoder (19 MiB, t=2, p=1), deny-by-default rules, CSP |
| `web/AuthController.java` | The two-step flow: `/login` → `/mfa` (or `/enrol`) → authenticated |
| `src/test/...` | RFC 4226 and RFC 4648 test vectors, replay and window tests |
| `deploy/` | Nginx config with TLS and per-IP rate limiting, certificate script |

## 2. Prerequisites

- JDK 21 (`sudo apt install openjdk-21-jdk`)
- Maven 3.9+ (`sudo apt install maven`)
- Docker with the compose plugin, for MySQL (not needed for the `dev` profile)
- `oath-toolkit` on the client machine (`sudo apt install oathtool`), and optionally KeePassXC

**Netlab note.** The build downloads dependencies from Maven Central. If the lab VMs have no
route out, build on a machine that does (`mvn -B package`) and copy `target/mfa-poc-0.1.0.jar`
to `vm-app` with `scp`. The same applies to the MySQL image: either `docker compose pull` where
there is internet and move the image with `docker save` / `docker load`, or run with the `dev`
profile, which uses an in-memory database and needs nothing.

## 3. Run it in two minutes (no infrastructure)

```bash
export POC_SECRET_KEY="$(openssl rand -base64 32)"
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

Open `http://localhost:8080/login`. Sign in as `admin` / `Admin-PoC-2026!` — that account has
`mfaRequired`, so it goes straight to enrolment. Add the secret to your generator:

```bash
oathtool --totp -b "THE-SECRET-FROM-THE-PAGE"
```

Type the code, enable the factor, write down the recovery codes, and you are in. The
`requester` account (`Requester-PoC-2026!`) starts without a second factor, so you can show
the one-factor and two-factor flows side by side.

## 4. Run it in the lab

On `vm-app`:

```bash
# 1. database
docker compose up -d

# 2. secrets and seed passwords — never commit these
export POC_SECRET_KEY="$(openssl rand -base64 32)"
export DB_PASSWORD="<the password from docker-compose>"
export POC_REQUESTER_PASSWORD="<choose>"
export POC_ADMIN_PASSWORD="<choose>"

# 3. application
mvn -B package
java -jar target/mfa-poc-0.1.0.jar

# 4. TLS front end
./deploy/make-cert.sh mfa-poc.lab 10.0.0.10
sudo cp deploy/nginx-mfa-poc.conf /etc/nginx/sites-available/mfa-poc
sudo ln -s /etc/nginx/sites-available/mfa-poc /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

On `vm-client`, add `10.0.0.10 mfa-poc.lab` to `/etc/hosts` and browse to
`https://mfa-poc.lab/login`. Keep the clocks in step on every VM:

```bash
sudo apt install chrony
sudo timedatectl set-ntp true
timedatectl   # check "System clock synchronized: yes" before each run
```

## 5. The eleven test cases

These are the cases listed in BoK section 6.1.5. Run them in order and capture the screen or
the terminal for each. `$SECRET` is the Base32 secret shown during enrolment.

| # | How to run it | What should happen |
|---|---|---|
| 1 | Sign in, then `oathtool --totp -b "$SECRET"` and enter the code | Home page shows the username and `[ROLE_ADMIN]` |
| 2 | Same, but type `000000` | "That code is not valid", still on the code page |
| 3 | After step 1 of the login, browse directly to `https://mfa-poc.lab/` | Redirected to `/login`: the pending session has no authorities |
| 4 | Use one code twice, inside the same 30 seconds | First accepted, second rejected |
| 5 | `oathtool --totp -b "$SECRET" --now "$(date -u -d '-30 seconds' '+%Y-%m-%d %H:%M:%S UTC')"` | Accepted: the window tolerates one step |
| 6 | Same with `-90 seconds` | Rejected: three steps old |
| 7 | On `vm-client`: `sudo timedatectl set-ntp false && sudo date -s '+2 minutes'`, generate a code | Rejected; restore with `sudo timedatectl set-ntp true` |
| 8 | Eleven wrong codes in a row (see the loop below) | Lockout, `MFA_LOCKOUT` in the audit log, further attempts rejected for 15 minutes |
| 9 | Sign in with a recovery code, then try the same one again | First accepted, second rejected |
| 10 | Capture the TLS login and open it in Arkime | Only handshake and encrypted records; no password, code or cookie |
| 11 | Repeat against `http://mfa-poc.lab:8081` and open that in Arkime | `username=…&password=…` and the code readable in the request body |

Lockout loop for case 8:

```bash
for i in $(seq 1 11); do
  echo -n "attempt $i: "
  curl -sk -o /dev/null -w "%{http_code}\n" https://mfa-poc.lab/mfa \
       -b cookies.txt -c cookies.txt -d "code=000000"
done
tail -f logs/audit.log
```

Capture and import for cases 10 and 11, on `vm-app` then `vm-arkime`:

```bash
# vm-app
sudo tcpdump -i any -w ~/login-tls.pcap 'port 443 or port 8081'
#   ... perform the login on vm-client, then Ctrl-C
scp ~/login-tls.pcap arkime@vm-arkime:~/

# vm-arkime
/opt/arkime/bin/capture -r ~/login-tls.pcap
```

For case 11 the session cookie will not be set over plaintext, because the cookie is marked
`Secure`. That refusal is itself evidence worth a screenshot. To complete the flow over HTTP,
start the app with `--server.servlet.session.cookie.secure=false` for that one run only, and
say so in the report.

## 6. The audit trail

Every run writes `logs/audit.log`, one JSON object per line:

```json
{"ts":"2026-10-01T09:14:22.118Z","event":"LOGIN_PASSWORD","actor":"admin","outcome":"SUCCESS","src_ip":"10.0.0.20","session":"3f9a1c77b2d4"}
{"ts":"2026-10-01T09:14:31.902Z","event":"MFA_VERIFY","actor":"admin","outcome":"FAILURE","src_ip":"10.0.0.20","session":"3f9a1c77b2d4","failed_count":"1"}
```

Events: `LOGIN_PASSWORD`, `LOGIN_BLOCKED`, `LOGIN_COMPLETE`, `MFA_VERIFY`, `MFA_LOCKOUT`,
`MFA_ENROL_START`, `MFA_ENROL_CONFIRM`. No secret, code, password or raw session id is ever
written: the session field is the first six bytes of a SHA-256 of the id.

## 7. Tests

```bash
mvn test
```

`TotpServiceTest` checks the implementation against the ten official test vectors of
RFC 4226 Appendix D, then covers replay, the window boundary and malformed input.
`Base32Test` checks the RFC 4648 vectors and round-trips random secrets. Run this before the
assessment: "it matches the RFC's own vectors" is a stronger claim than "it worked when I
tried it".

## 8. Troubleshooting

| Symptom | Cause |
|---|---|
| Every code is rejected | Clock drift. Check `timedatectl` on both VMs; a snapshot restore is the usual culprit |
| `poc.secret-key must decode to 32 bytes` | `POC_SECRET_KEY` is unset or not 32 random bytes in base64 |
| `NoClassDefFoundError: org/bouncycastle/...` | The BouncyCastle dependency did not resolve; Argon2PasswordEncoder needs it |
| Login succeeds but you bounce back to `/login` | The session cookie is `Secure` and you are on plaintext HTTP; use HTTPS or the `dev` profile |
| Nginx returns 502 | The app binds to `127.0.0.1:8080` by default; check it is running on the same host as Nginx |
| MySQL connection refused | `docker compose up -d` and wait for the container to become healthy |

## 9. Known limits

Written down because they belong in the report rather than in a demo that claims more than it shows:

- TOTP is phishable through a real-time relay; WebAuthn is the phishing-resistant answer.
- The encryption key comes from an environment variable, not a vault (that is PoC 6.4).
- The progressive delay blocks a request thread; acceptable here, not in production.
- `ddl-auto=update` creates the schema; a real deployment uses versioned migrations.
- There is no password pepper yet: SecureDesk adds it as part of SC-02.
