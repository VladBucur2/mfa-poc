package nl.fontys.mfapoc.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** One single-use recovery code, stored only as an Argon2id hash, exactly like a password. */
@Entity
@Table(name = "recovery_code")
public class RecoveryCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false, length = 255)
    private String codeHash;

    private Instant usedAt;

    protected RecoveryCode() {
    }

    public RecoveryCode(Long userId, String codeHash) {
        this.userId = userId;
        this.codeHash = codeHash;
    }

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public void markUsed(Instant usedAt) {
        this.usedAt = usedAt;
    }
}
