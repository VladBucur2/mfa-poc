# Local runbook: mfa-poc on your laptop, start to finish

The whole laboratory runs in Docker on your laptop. One `docker-compose.yml` describes it,
so it rebuilds from nothing with one command, and every step below is the same on Windows,
macOS and Linux: anything platform-specific happens inside a container.

| Role | Played by |
|---|---|
| System under test | Containers `app`, `mysql` and `nginx`; only `nginx` publishes a port, on `127.0.0.1` |
| The user's workstation | Your browser and a phone authenticator, plus a `client` container for the scripted cases |
| Traffic analysis | `capture` containers running `tcpdump` inside the Nginx container's network; Wireshark reads the result |

Run every command in a terminal in the `mfa-poc` folder: PowerShell or Windows Terminal on
Windows, Terminal on macOS. Type what follows the `$`, not the `$` itself.

Allow about two hours the first time, most of it for the tests and the screenshots.

---

## Phase 0 — Install three things

1. **Docker Desktop.** Windows: `winget install Docker.DockerDesktop`, or the installer from
   docker.com; accept the WSL 2 option, restart when asked, then start Docker Desktop once and
   wait until it says *Engine running*. macOS: the installer from docker.com. Check:

   ```bash
   $ docker version
   $ docker compose version
   ```

   The compose version must be **2.24 or newer**; if it is older, update Docker Desktop.
2. **Wireshark**, to read the captures. Windows: `winget install WiresharkFoundation.Wireshark`.
   macOS: `brew install --cask wireshark`, or the installer from wireshark.org.
3. **An authenticator app on your phone**: Aegis, Google Authenticator or Microsoft
   Authenticator. It reads the QR code straight off your screen.

You do not need Java or Maven on the laptop any more: the build and the tests run in
containers.

## Phase 1 — Set up the project

Unzip `mfa-poc.zip` and open a terminal in the `mfa-poc` folder.

```bash
$ docker compose run --rm setup
```

The first run builds the small tools image (a minute). Then it asks for two passwords, for the
`requester` and the `admin` account: at least 12 characters, letters, digits, `.`, `-` and `_`.
It creates three things, and never overwrites them on later runs:

| File | Contents |
|---|---|
| `.env` | The encryption key, database passwords and the two account passwords. **The key must never change** after the first start: the enrolled secrets are encrypted with it |
| `certs/` | A self-signed certificate for `mfa-poc.localhost` |
| `client.env` | Settings for the scripted tests; you fill it in during phase 4 |

`.env` and `client.env` hold secrets. Both are in `.gitignore`; keep it that way.

*Linux only:* files created inside a container belong to root there. Run
`sudo chown -R $USER: .env client.env certs captures` once afterwards.

## Phase 2 — Run the unit tests

```bash
$ docker compose run --rm test
```

The first run downloads Maven's dependencies and takes a few minutes. It must end with
`Tests run: 10, Failures: 0, Errors: 0` and `BUILD SUCCESS`. **Screenshot** that: it is your
evidence that the TOTP implementation matches the official RFC 4226 test vectors. This is
also the first time the code is ever compiled, so if anything fails here, stop and fix it
first.

## Phase 3 — Start the laboratory

```bash
$ docker compose up -d
```

This builds the application image (the build runs the same tests again: an image with a
broken TOTP implementation cannot be built), starts MySQL, waits until it is healthy, then
starts the application and Nginx. Check:

```bash
$ docker compose ps
```

`mysql` must be *healthy*, `app` and `nginx` *running*. Open a **second terminal** for the
application's log and keep it visible during every test: the lines starting `AUDIT` are your
audit trail, and most screenshots should include them.

```bash
$ docker compose logs -f app
```

Wait for `seeded account 'admin'` and `Started MfaPocApplication`. Then, in the first terminal:

```bash
$ docker compose run --rm client smoke
```

`HTTP 200` means the whole chain works: TLS, the certificate, Nginx and the application behind it.

**The browser.** Open **`https://mfa-poc.localhost:8443/login`**. Chrome, Edge and current
Firefox resolve any `*.localhost` name to your own machine without a hosts file. The browser
warns about the self-signed certificate: **screenshot** the warning (it belongs next to the
sentence in the report that a real deployment uses a certificate from a CA), then *Advanced*,
*Proceed* or *Accept the risk*.

Use `mfa-poc.localhost` rather than plain `localhost`: the site sends an HSTS header, and you
do not want any chance of your browser forcing HTTPS on the other `localhost` projects you work on.

## Phase 4 — Enrol the administrator

1. Sign in as `admin` with the password you chose. The account has `mfaRequired`, so you land
   on the enrolment page. **Screenshot** the QR code and the secret (blur the secret in the
   report).
2. Scan the QR code with your phone's authenticator.
3. Open `client.env` in a text editor and fill in `PASSWORD` with the admin password and
   `SECRET` with the secret shown on the page. Save it. Then:

   ```bash
   $ docker compose run --rm client code
   ```

   **Screenshot** this next to your phone showing the same number: two independent RFC 6238
   implementations agreeing with your server is evidence in itself.
4. Type the code into the page and press *Enable*. **Screenshot** the recovery codes and copy
   two of them into a note; case 9 needs them.
5. The home page shows `[ROLE_ADMIN]`; the log shows `MFA_ENROL_START`, `MFA_ENROL_CONFIRM` and
   `LOGIN_COMPLETE`.

## Phase 5 — The test cases

In this order, which is chosen so that no case spoils the next. For each, capture the screen or
terminal **and** the matching `AUDIT` lines from the log terminal.

**Case 1: two factors, and the difference with one.** Sign out, sign in as `admin` with
password and code: home shows `[ROLE_ADMIN]`, and *Administrator page* shows the user list.
Sign out, sign in as `requester`: no code is asked, home shows `[ROLE_REQUESTER]`, and
*Administrator page* gives **403**. Audit: `"factors":"2"` for admin, `"factors":"1"` for
requester.

**Case 2: wrong code.** Sign in as admin and type `000000`: *That code is not valid*. Audit:
`MFA_VERIFY` `FAILURE` with `failed_count` 1. Finish with the right code, which resets the counter.

**Case 3: the pending session is powerless.**

```bash
$ docker compose run --rm client case3
```

`GET /` after a correct password must answer `302` to `/login`.

**Case 4: a code works once.**

```bash
$ docker compose run --rm client case4
```

The first use redirects to `/`; the second is rejected.

> **Wait 90 seconds now.** The server remembers the last accepted time step and refuses
> anything at or before it. Case 5 deliberately uses an older step, so going straight on
> would get it refused for the wrong reason.

**Case 5: the previous window is accepted.** In the browser, sign in with the password; then:

```bash
$ docker compose run --rm client codes
```

Enter the **30 s** code straight away: accepted. It belongs to the previous time step and is
only valid until the current one ends, so if it is rejected the window just rolled over: run
`codes` again and be quicker.

**Case 6: an old code is refused.** Sign in again and enter the **90 s** code from a fresh
`codes` run: rejected, three steps too old. Finish with the current code.

**Case 7: clock skew.** Your laptop has one clock, so the skew is simulated:

```bash
$ docker compose run --rm client skew
```

It prints the code a client whose clock runs two minutes fast would show. Sign in and enter
it: rejected, because it lies four time steps ahead of the server.

**Case 9: recovery codes are single use.** Sign in and enter a recovery code instead of a TOTP
code: home page. Audit: `MFA_VERIFY` with `"method":"recovery_code"` and a separate
`MFA_RECOVERY_USED` with `"alert":"true"`. Sign out and try the same recovery code: rejected.

**Cases 10 and 11:** phase 6.

**Case 12: the reset path is visible.** As admin, open *Administrator page* and press *Reset
MFA* on the admin row. Audit: `MFA_RESET` with `"alert":"true"` and the target. Sign out and in
again: you are sent to enrolment with a **new** secret, and the entry on your phone no longer
works. Delete it, enrol again, and update `SECRET` in `client.env`.

**Case 8: lockout. Last, because it locks the account.**

```bash
$ docker compose run --rm client case8
```

Attempts slow down (0, 1, 2, 4, then 8 seconds), attempt 10 locks the account and ends the
session, attempt 11 is refused with 403, and a fresh login with the right password is
refused. Audit: rising `failed_count`, then `MFA_LOCKOUT`, then `LOGIN_BLOCKED`. Then the
network layer:

```bash
$ docker compose run --rm client ratelimit
```

About eleven requests pass; the rest get **429** from Nginx without reaching the application.
The account stays locked for fifteen minutes.

## Phase 6 — Captures for cases 10 and 11, read in Wireshark

**Case 10: the login over TLS.** In the first terminal:

```bash
$ docker compose run --rm capture-tls case10-tls
```

When it says *Capturing*, sign in as admin in the browser with password and code, then press
**Ctrl-c** in the terminal. Open `captures/case10-tls.pcap` in Wireshark and filter on `tls`:
the handshake shows TLS 1.3, after which there is only *Application Data*. Right-click a packet,
*Follow*, *TCP Stream*: unreadable. **Screenshot.**

**Case 11: the same login without TLS.** Start the plaintext listener, then the capture:

```bash
$ docker compose --profile plaintext up -d nginx-plain
$ docker compose --profile plaintext run --rm capture-plain case11-plain
```

In the browser open **`http://127.0.0.1:8081/login`**: the address, not `mfa-poc.localhost`.
After your first HTTPS visit, the site's HSTS header allows the browser to upgrade any later
plain-HTTP request for `mfa-poc.localhost` to HTTPS on its own, which would break this test.
Browsers differ in how they treat HSTS for `localhost` names, but HSTS never applies to an IP
address, so `127.0.0.1` always works. If your browser does upgrade `http://mfa-poc.localhost:8081`,
that is HSTS doing its job and worth a screenshot.

Sign in at `127.0.0.1:8081`. You land back on the sign-in page: the browser refused the
session cookie because it is marked `Secure`. **Screenshot that too**: it is the cookie flag
doing its job. Press Ctrl-c, open `captures/case11-plain.pcap` in Wireshark, filter on
`http.request.method == "POST"`, and *Follow*, *HTTP Stream* on the `/login` request:
`username=admin&password=...` in the clear. **Screenshot**, with the password blurred.

To show the code and the session cookie in the clear as well, run the full flow once with the
cookie flag off:

```bash
$ docker compose -f docker-compose.yml -f compose.insecure-cookie.yml up -d app
$ docker compose --profile plaintext run --rm capture-plain case11-full
```

Wait until the log terminal shows `Started MfaPocApplication`, then sign in fully at
`http://127.0.0.1:8081/login`, password and code. Ctrl-c. In `case11-full.pcap`, the `/mfa`
request shows `code=` and the six digits, and the response's `Set-Cookie` shows the session id.
State in the report that the flag was off for this one capture only. **Restore at once:**

```bash
$ docker compose up -d app
$ docker compose --profile plaintext stop nginx-plain
```

The case 11 captures contain your real admin password. Delete them from `captures/` once the
screenshots exist.

## Phase 7 — Collect the evidence

```bash
$ mkdir evidence
$ docker compose cp app:/app/logs/audit.log evidence/audit.log
```

Name the screenshots after the report's table (`case01-two-factors.png`, `case08-lockout.png`,
...) so each row of 6.1.5 points at a file. The full set:

- the `docker compose run --rm test` summary with the RFC 4226 vectors passing
- enrolment page, phone and `client code` agreeing, recovery codes page
- one screenshot or terminal capture per case, 1 to 12, with its `AUDIT` lines
- the browser's certificate warning, and the HSTS refusal if you captured it
- Wireshark: case 10 (unreadable), case 11 (password readable), case 11 full (code and cookie readable)
- the 429 responses from the rate limit
- `evidence/audit.log`, the source behind every claim about logging

## Phase 8 — Stop, reset, and the live demo

```bash
$ docker compose down          # stops everything, keeps the database and the log
$ docker compose down -v       # also wipes them: next start begins with no enrolments
```

For the assessment: `docker compose up -d`, wait for the application to start, and show cases
1, 3 and 4 live. That takes five minutes, and the Wireshark screenshots cover the rest. If an
earlier run left the admin locked or enrolled with a phone you no longer have, `down -v`
first and enrol again.

---

## When something goes wrong

| Symptom | Cause and fix |
|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop is not running. Start it and wait for *Engine running* |
| `env_file` error, or `required` not recognised | Docker Compose older than 2.24. Update Docker Desktop |
| `app` keeps restarting | `docker compose logs app`. *secret-key must decode to 32 bytes*: run `setup`. *Access denied*: see the next row |
| MySQL `Access denied` | `.env` changed after the database was first created. `docker compose down -v`, then `up -d` |
| `decryption failed` in the log | `POC_SECRET_KEY` in `.env` changed. Restore it, or `down -v` and enrol again |
| `bash\r: No such file or directory` | A script got Windows line endings, usually through Git. The included `.gitattributes` prevents this; re-extract the zip |
| Browser cannot find `mfa-poc.localhost` | Use Chrome or Edge, or update Firefox |
| Every code is rejected | The laptop's or the phone's clock is off. Windows: *Settings*, *Time & language*, *Sync now*. The phone: automatic time on |
| Back on `/login` straight after the password | Plain HTTP with a `Secure` cookie. Use `https://mfa-poc.localhost:8443` |
| `PASSWORD is empty` or `SECRET is empty` | Fill in `client.env` (phase 4) |
| 429 from Nginx | The rate limit. Wait a minute |
| 502 from Nginx | The application is still starting, or crashed: check the log terminal |
| Port 8443 or 8081 already in use | Change the left-hand port in `docker-compose.yml`, for example `127.0.0.1:9443:443`, and use that in the browser |
| Wireshark shows nothing useful | The capture was stopped before the login finished, or started after it |
