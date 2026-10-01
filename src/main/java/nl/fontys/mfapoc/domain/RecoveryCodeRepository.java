package nl.fontys.mfapoc.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {
    List<RecoveryCode> findByUserIdAndUsedAtIsNull(Long userId);
    void deleteByUserId(Long userId);
}
