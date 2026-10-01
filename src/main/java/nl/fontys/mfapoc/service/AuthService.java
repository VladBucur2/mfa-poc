package nl.fontys.mfapoc.service;

import jakarta.transaction.Transactional;
import nl.fontys.mfapoc.domain.AppUser;
import nl.fontys.mfapoc.domain.AppUserRepository;
import nl.fontys.mfapoc.domain.RecoveryCode;
import nl.fontys.mfapoc.domain.RecoveryCodeRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** All authentication decisions live here; the controllers only translate them to HTTP. */
@Service
public class AuthService {

    public enum MfaOutcome { OK, INVALID, LOCKED }

    private static final int MAX_FAILED_MFA = 10;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    private static final int[] DELAY_SECONDS = {0, 1, 2, 4, 8};
    private static final int RECOVERY_CODE_COUNT = 10;

    private final AppUserRepository users;
    private final RecoveryCodeRepository recoveryCodes;
    private final PasswordEncoder encoder;
    private final TotpService totp;
    private final SecretCipher cipher;
    private final SecureRandom random = new SecureRandom();

    /**
     * A hash of a random value, computed once at startup. Verifying an unknown username
     * against it costs the same as verifying a real one, so response time does not reveal
     * whether an account exists.
     */
    private final String dummyHash;

    public AuthService(AppUserRepository users, RecoveryCodeRepository recoveryCodes,
                       PasswordEncoder encoder, TotpService totp, SecretCipher cipher) {
        this.users = users;
        this.recoveryCodes = recoveryCodes;
        this.encoder = encoder;
        this.totp = totp;
        this.cipher = cipher;
        this.dummyHash = encoder.encode(UUID.randomUUID().toString());
    }

    public Optional<AppUser> verifyPassword(String username, String rawPassword) {
        Optional<AppUser> found = users.findByUsername(username == null ? "" : username.trim());
        if (found.isEmpty()) {
            encoder.matches(rawPassword == null ? "" : rawPassword, dummyHash);
            return Optional.empty();
        }
        AppUser user = found.get();
        if (!encoder.matches(rawPassword == null ? "" : rawPassword, user.getPasswordHash())) {
            return Optional.empty();
        }
        return Optional.of(user);
    }

    /** Starts enrolment: a new secret is stored encrypted, but MFA stays off until confirmed. */
    @Transactional
    public String beginEnrolment(AppUser user) {
        String secret = totp.newSecretBase32();
        user.setTotpSecretEncrypted(cipher.encrypt(secret));
        user.setMfaEnabled(false);
        user.setLastAcceptedStep(-1);
        users.save(user);
        return secret;
    }

    /** Confirms enrolment with a live code, then issues the recovery codes exactly once. */
    @Transactional
    public Optional<List<String>> completeEnrolment(AppUser user, String code, Instant now) {
        if (user.getTotpSecretEncrypted() == null) {
            return Optional.empty();
        }
        String secret = cipher.decrypt(user.getTotpSecretEncrypted());
        long step = totp.verify(secret, code, now, user.getLastAcceptedStep());
        if (step < 0) {
            return Optional.empty();
        }
        user.setMfaEnabled(true);
        user.setLastAcceptedStep(step);
        user.setFailedMfaCount(0);
        user.setLockedUntil(null);
        users.save(user);

        recoveryCodes.deleteByUserId(user.getId());
        List<String> plain = new ArrayList<>();
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            String value = randomRecoveryCode();
            plain.add(value);
            recoveryCodes.save(new RecoveryCode(user.getId(), encoder.encode(value)));
        }
        return Optional.of(plain);
    }

    @Transactional
    public MfaOutcome verifyMfa(AppUser user, String input, Instant now) {
        if (user.isLocked(now)) {
            return MfaOutcome.LOCKED;
        }
        applyProgressiveDelay(user.getFailedMfaCount());

        String secret = cipher.decrypt(user.getTotpSecretEncrypted());
        long step = totp.verify(secret, input, now, user.getLastAcceptedStep());
        if (step >= 0) {
            user.setLastAcceptedStep(step);
            user.setFailedMfaCount(0);
            users.save(user);
            return MfaOutcome.OK;
        }

        if (consumeRecoveryCode(user, input, now)) {
            user.setFailedMfaCount(0);
            users.save(user);
            return MfaOutcome.OK;
        }

        int failed = user.getFailedMfaCount() + 1;
        if (failed >= MAX_FAILED_MFA) {
            user.setFailedMfaCount(0);
            user.setLockedUntil(now.plus(LOCK_DURATION));
            users.save(user);
            return MfaOutcome.LOCKED;
        }
        user.setFailedMfaCount(failed);
        users.save(user);
        return MfaOutcome.INVALID;
    }

    private boolean consumeRecoveryCode(AppUser user, String input, Instant now) {
        if (input == null || input.isBlank()) {
            return false;
        }
        String candidate = input.trim().toUpperCase();
        for (RecoveryCode stored : recoveryCodes.findByUserIdAndUsedAtIsNull(user.getId())) {
            if (encoder.matches(candidate, stored.getCodeHash())) {
                stored.markUsed(now);
                recoveryCodes.save(stored);
                return true;
            }
        }
        return false;
    }

    /**
     * Slows an attacker down per account. Blocking the request thread is acceptable for a
     * proof of concept; a production implementation would do this without holding a thread.
     */
    private void applyProgressiveDelay(int failedCount) {
        int index = Math.min(failedCount, DELAY_SECONDS.length - 1);
        int seconds = DELAY_SECONDS[index];
        if (seconds == 0) {
            return;
        }
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String randomRecoveryCode() {
        byte[] raw = new byte[5];
        random.nextBytes(raw);
        String encoded = Base32.encode(raw);
        return encoded.substring(0, 4) + "-" + encoded.substring(4);
    }
}
