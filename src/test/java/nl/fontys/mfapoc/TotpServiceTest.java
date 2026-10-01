package nl.fontys.mfapoc;

import nl.fontys.mfapoc.service.Base32;
import nl.fontys.mfapoc.service.TotpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The first test is the important one: it checks this implementation against the official
 * test vectors of RFC 4226 Appendix D, so the truncation is verified rather than assumed.
 */
class TotpServiceTest {

    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final String[] RFC_CODES = {
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489"
    };

    private final TotpService totp = new TotpService("MfaPoC");

    @Test
    @DisplayName("matches the RFC 4226 test vectors for counters 0 to 9")
    void matchesRfcTestVectors() {
        for (int counter = 0; counter < RFC_CODES.length; counter++) {
            assertEquals(RFC_CODES[counter], totp.generate(RFC_SECRET, counter),
                    "counter " + counter);
        }
    }

    @Test
    @DisplayName("accepts the code of the current time step")
    void acceptsCurrentStep() {
        String secret = totp.newSecretBase32();
        Instant now = Instant.now();
        String code = totp.generate(Base32.decode(secret), totp.currentStep(now));

        assertEquals(totp.currentStep(now), totp.verify(secret, code, now, -1));
    }

    @Test
    @DisplayName("rejects a code that was already accepted (replay)")
    void rejectsReplay() {
        String secret = totp.newSecretBase32();
        Instant now = Instant.now();
        long step = totp.currentStep(now);
        String code = totp.generate(Base32.decode(secret), step);

        assertEquals(step, totp.verify(secret, code, now, -1));
        assertEquals(-1, totp.verify(secret, code, now, step), "the same code must not work twice");
    }

    @Test
    @DisplayName("accepts the previous step but not one three steps old")
    void toleratesOneStepOnly() {
        String secret = totp.newSecretBase32();
        Instant now = Instant.now();
        long current = totp.currentStep(now);

        String previous = totp.generate(Base32.decode(secret), current - 1);
        String old = totp.generate(Base32.decode(secret), current - 3);

        assertEquals(current - 1, totp.verify(secret, previous, now, -1));
        assertEquals(-1, totp.verify(secret, old, now, -1));
    }

    @Test
    @DisplayName("rejects anything that is not six digits")
    void rejectsMalformedInput() {
        String secret = totp.newSecretBase32();
        Instant now = Instant.now();

        assertEquals(-1, totp.verify(secret, "12345", now, -1));
        assertEquals(-1, totp.verify(secret, "abcdef", now, -1));
        assertEquals(-1, totp.verify(secret, null, now, -1));
    }

    @Test
    @DisplayName("generates a fresh 160-bit secret every time")
    void generatesDistinctSecrets() {
        String first = totp.newSecretBase32();
        String second = totp.newSecretBase32();

        assertEquals(20, Base32.decode(first).length);
        assertNotEquals(first, second);
    }

    @Test
    @DisplayName("builds an otpauth URI an authenticator can read")
    void buildsOtpAuthUri() {
        String secret = totp.newSecretBase32();
        String uri = totp.otpAuthUri("admin", secret);

        assertTrue(uri.startsWith("otpauth://totp/MfaPoC:admin?"));
        assertTrue(uri.contains("secret=" + secret));
        assertTrue(uri.contains("period=30"));
    }
}
