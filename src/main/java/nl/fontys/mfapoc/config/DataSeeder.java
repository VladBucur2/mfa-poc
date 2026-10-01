package nl.fontys.mfapoc.config;

import nl.fontys.mfapoc.domain.AppUser;
import nl.fontys.mfapoc.domain.AppUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Creates the two demonstration accounts. Neither password nor secret is ever logged. */
@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger LOG = LoggerFactory.getLogger(DataSeeder.class);

    private final AppUserRepository users;
    private final PasswordEncoder encoder;
    private final String requesterPassword;
    private final String adminPassword;

    public DataSeeder(AppUserRepository users, PasswordEncoder encoder,
                      @Value("${poc.seed.requester-password}") String requesterPassword,
                      @Value("${poc.seed.admin-password}") String adminPassword) {
        this.users = users;
        this.encoder = encoder;
        this.requesterPassword = requesterPassword;
        this.adminPassword = adminPassword;
    }

    @Override
    public void run(String... args) {
        seed("requester", requesterPassword, "ROLE_REQUESTER", false);
        seed("admin", adminPassword, "ROLE_ADMIN", true);
    }

    private void seed(String username, String password, String role, boolean mfaRequired) {
        if (users.findByUsername(username).isPresent()) {
            return;
        }
        users.save(new AppUser(username, encoder.encode(password), role, mfaRequired));
        LOG.info("seeded account '{}' with role {} (mfaRequired={})", username, role, mfaRequired);
    }
}
