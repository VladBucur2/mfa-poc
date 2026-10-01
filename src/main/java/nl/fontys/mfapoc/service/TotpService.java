package nl.fontys.mfapoc.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * RFC 6238 TOTP verification.
 *
 * The cryptography is the JDK's HmacSHA1. What is implemented here is the dynamic
 * truncation of RFC 4226 and the time-window logic; both are covered by the RFC's own
 * test vectors in TotpServiceTest.
 */
@Service
public class TotpService {

    public static final int DIGITS = 6;
    public static final int STEP_SECONDS = 30;
    /** Accept the previous and next step, so a slow typist or small drift still works. */
    public static final int WINDOW_STEPS = 1;

    private static final int SECRET_BYTES = 20; // 160 bits, as RFC 4226 recommends for SHA-1

    private final SecureRandom random = new SecureRandom();
    private final String issuer;

    public TotpService(@Value("${poc.issuer:MfaPoC}") String issuer) {
        this.issuer = issuer;
    }

    public String newSecretBase32() {
        byte[] secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        return Base32.encode(secret);
    }

    public String otpAuthUri(String account, String secretBase32) {
        String issuerEncoded = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        String accountEncoded = URLEncoder.encode(account, StandardCharsets.UTF_8);
        return "otpauth://totp/" + issuerEncoded + ":" + accountEncoded
                + "?secret=" + secretBase32
                + "&issuer=" + issuerEncoded
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    public long currentStep(Instant now) {
        return now.getEpochSecond() / STEP_SECONDS;
    }

    /**
     * Verifies a code and returns the time step it belongs to, or -1 when it is not valid.
     *
     * Steps at or below lastAcceptedStep are skipped, which is what makes a code single use:
     * once a step has been accepted for this user, no code from that step or an older one is
     * accepted again, even though it is still inside the tolerance window.
     */
    public long verify(String secretBase32, String code, Instant now, long lastAcceptedStep) {
        if (code == null || !code.matches("\\d{" + DIGITS + "}")) {
            return -1;
        }
        byte[] key = Base32.decode(secretBase32);
        long current = currentStep(now);
        for (long step = current - WINDOW_STEPS; step <= current + WINDOW_STEPS; step++) {
            if (step <= lastAcceptedStep) {
                continue;
            }
            if (constantTimeEquals(generate(key, step), code)) {
                return step;
            }
        }
        return -1;
    }

    /** HOTP of RFC 4226: HMAC-SHA1 over the counter, then dynamic truncation. */
    public String generate(byte[] key, long counter) {
        try {
            byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int modulus = (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", binary % modulus);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
