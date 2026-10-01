package nl.fontys.mfapoc.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "app_user")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String username;

    @Column(nullable = false, length = 255)
    private String passwordHash;

    /** ROLE_REQUESTER or ROLE_ADMIN. */
    @Column(nullable = false, length = 32)
    private String role;

    /** True when the role may not skip enrolment (administrators). */
    @Column(nullable = false)
    private boolean mfaRequired;

    /** True only after enrolment has been confirmed with a valid code. */
    @Column(nullable = false)
    private boolean mfaEnabled;

    /** AES-256-GCM ciphertext of the Base32 secret; null before enrolment starts. */
    @Column(length = 255)
    private String totpSecretEncrypted;

    /** Highest TOTP time step already accepted for this user: blocks replay. */
    @Column(nullable = false)
    private long lastAcceptedStep = -1;

    @Column(nullable = false)
    private int failedMfaCount;

    private Instant lockedUntil;

    protected AppUser() {
    }

    public AppUser(String username, String passwordHash, String role, boolean mfaRequired) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.mfaRequired = mfaRequired;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getRole() {
        return role;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public String getTotpSecretEncrypted() {
        return totpSecretEncrypted;
    }

    public void setTotpSecretEncrypted(String totpSecretEncrypted) {
        this.totpSecretEncrypted = totpSecretEncrypted;
    }

    public long getLastAcceptedStep() {
        return lastAcceptedStep;
    }

    public void setLastAcceptedStep(long lastAcceptedStep) {
        this.lastAcceptedStep = lastAcceptedStep;
    }

    public int getFailedMfaCount() {
        return failedMfaCount;
    }

    public void setFailedMfaCount(int failedMfaCount) {
        this.failedMfaCount = failedMfaCount;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }
}
