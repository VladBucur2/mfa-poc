package nl.fontys.mfapoc.web;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nl.fontys.mfapoc.domain.AppUser;
import nl.fontys.mfapoc.domain.AppUserRepository;
import nl.fontys.mfapoc.service.AuditLog;
import nl.fontys.mfapoc.service.AuthService;
import nl.fontys.mfapoc.service.TotpService;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Controller
public class AuthController {

    /** The id of the user who passed step one. Never an authenticated principal. */
    private static final String PENDING_USER = "PENDING_USER";
    /** Either "MFA" (enrolled, needs a code) or "ENROL" (must enrol before continuing). */
    private static final String PENDING_MODE = "PENDING_MODE";
    private static final String ENROLMENT_SECRET = "ENROLMENT_SECRET";
    private static final String RECOVERY_CODES = "RECOVERY_CODES";

    private static final String GENERIC_ERROR = "Those details are not correct.";

    private final AuthService auth;
    private final AppUserRepository users;
    private final TotpService totp;
    private final AuditLog audit;
    private final SecurityContextRepository contextRepository;

    public AuthController(AuthService auth, AppUserRepository users, TotpService totp,
                          AuditLog audit, SecurityContextRepository contextRepository) {
        this.auth = auth;
        this.users = users;
        this.totp = totp;
        this.audit = audit;
        this.contextRepository = contextRepository;
    }

    // ---------------------------------------------------------------- step 1: password

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpServletRequest request, HttpServletResponse response, Model model) {
        Optional<AppUser> verified = auth.verifyPassword(username, password);
        if (verified.isEmpty()) {
            audit.event("LOGIN_PASSWORD", username, "FAILURE", request);
            model.addAttribute("error", GENERIC_ERROR);
            return "login";
        }

        AppUser user = verified.get();
        audit.event("LOGIN_PASSWORD", user.getUsername(), "SUCCESS", request);

        if (user.isLocked(Instant.now())) {
            audit.event("LOGIN_BLOCKED", user.getUsername(), "LOCKED", request);
            model.addAttribute("error", GENERIC_ERROR);
            return "login";
        }

        HttpSession session = request.getSession(true);
        session.setAttribute(PENDING_USER, user.getId());

        if (user.isMfaEnabled()) {
            session.setAttribute(PENDING_MODE, "MFA");
            return "redirect:/mfa";
        }
        if (user.isMfaRequired()) {
            session.setAttribute(PENDING_MODE, "ENROL");
            return "redirect:/enrol";
        }
        // No second factor configured and none required: this account is weaker on purpose,
        // so that the difference between one and two factors can be demonstrated.
        completeAuthentication(user, request, response);
        audit.event("LOGIN_COMPLETE", user.getUsername(), "SUCCESS", request,
                Map.of("factors", "1"));
        return "redirect:/";
    }

    // ---------------------------------------------------------------- step 2: the code

    @GetMapping("/mfa")
    public String mfaPage(HttpServletRequest request) {
        return pendingUser(request, "MFA").isPresent() ? "mfa" : "redirect:/login";
    }

    @PostMapping("/mfa")
    public String mfa(@RequestParam String code, HttpServletRequest request,
                      HttpServletResponse response, Model model) {
        Optional<AppUser> pending = pendingUser(request, "MFA");
        if (pending.isEmpty()) {
            return "redirect:/login";
        }
        AppUser user = pending.get();

        AuthService.MfaOutcome outcome = auth.verifyMfa(user, code, Instant.now());
        switch (outcome) {
            case OK -> {
                completeAuthentication(user, request, response);
                audit.event("MFA_VERIFY", user.getUsername(), "SUCCESS", request);
                audit.event("LOGIN_COMPLETE", user.getUsername(), "SUCCESS", request,
                        Map.of("factors", "2"));
                return "redirect:/";
            }
            case LOCKED -> {
                audit.event("MFA_LOCKOUT", user.getUsername(), "LOCKED", request);
                request.getSession().invalidate();
                model.addAttribute("error", GENERIC_ERROR);
                return "login";
            }
            default -> {
                audit.event("MFA_VERIFY", user.getUsername(), "FAILURE", request,
                        Map.of("failed_count", String.valueOf(user.getFailedMfaCount())));
                model.addAttribute("error", "That code is not valid.");
                return "mfa";
            }
        }
    }

    // ---------------------------------------------------------------- enrolment

    @GetMapping("/enrol")
    public String enrolPage(HttpServletRequest request, Model model) {
        Optional<AppUser> pending = pendingUser(request, "ENROL");
        if (pending.isEmpty()) {
            return "redirect:/login";
        }
        AppUser user = pending.get();
        HttpSession session = request.getSession();

        String secret = (String) session.getAttribute(ENROLMENT_SECRET);
        if (secret == null) {
            secret = auth.beginEnrolment(user);
            session.setAttribute(ENROLMENT_SECRET, secret);
            audit.event("MFA_ENROL_START", user.getUsername(), "SUCCESS", request);
        }
        model.addAttribute("secret", secret);
        model.addAttribute("uri", totp.otpAuthUri(user.getUsername(), secret));
        return "enrol";
    }

    /** The QR image is rendered from the session, so the secret never travels in a URL. */
    @GetMapping(value = "/enrol/qr.png", produces = MediaType.IMAGE_PNG_VALUE)
    @ResponseBody
    public byte[] enrolQr(HttpServletRequest request) throws Exception {
        Optional<AppUser> pending = pendingUser(request, "ENROL");
        String secret = (String) request.getSession().getAttribute(ENROLMENT_SECRET);
        if (pending.isEmpty() || secret == null) {
            return new byte[0];
        }
        String uri = totp.otpAuthUri(pending.get().getUsername(), secret);
        BitMatrix matrix = new QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 240, 240);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", out);
        return out.toByteArray();
    }

    @PostMapping("/enrol")
    public String enrol(@RequestParam String code, HttpServletRequest request,
                        HttpServletResponse response, Model model) {
        Optional<AppUser> pending = pendingUser(request, "ENROL");
        if (pending.isEmpty()) {
            return "redirect:/login";
        }
        AppUser user = pending.get();

        Optional<List<String>> codes = auth.completeEnrolment(user, code, Instant.now());
        if (codes.isEmpty()) {
            audit.event("MFA_ENROL_CONFIRM", user.getUsername(), "FAILURE", request);
            model.addAttribute("error", "That code is not valid; the factor was not enabled.");
            String secret = (String) request.getSession().getAttribute(ENROLMENT_SECRET);
            model.addAttribute("secret", secret);
            model.addAttribute("uri", totp.otpAuthUri(user.getUsername(), secret));
            return "enrol";
        }

        audit.event("MFA_ENROL_CONFIRM", user.getUsername(), "SUCCESS", request);
        HttpSession session = request.getSession();
        session.removeAttribute(ENROLMENT_SECRET);
        completeAuthentication(user, request, response);
        // Shown exactly once, on the next page, then dropped from the session.
        request.getSession().setAttribute(RECOVERY_CODES, codes.get());
        return "redirect:/recovery";
    }

    @GetMapping("/recovery")
    public String recovery(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(RECOVERY_CODES) == null) {
            return "redirect:/";
        }
        model.addAttribute("codes", session.getAttribute(RECOVERY_CODES));
        session.removeAttribute(RECOVERY_CODES);
        return "recovery";
    }

    // ---------------------------------------------------------------- helpers

    private Optional<AppUser> pendingUser(HttpServletRequest request, String expectedMode) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }
        Object id = session.getAttribute(PENDING_USER);
        Object mode = session.getAttribute(PENDING_MODE);
        if (id == null || !expectedMode.equals(mode)) {
            return Optional.empty();
        }
        return users.findById((Long) id);
    }

    /**
     * Promotes the pending session to an authenticated one. The session id is rotated first,
     * so a session fixated before login cannot survive into the authenticated state.
     */
    private void completeAuthentication(AppUser user, HttpServletRequest request,
                                        HttpServletResponse response) {
        HttpSession session = request.getSession();
        session.removeAttribute(PENDING_USER);
        session.removeAttribute(PENDING_MODE);
        request.changeSessionId();

        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                user.getUsername(), null, List.of(new SimpleGrantedAuthority(user.getRole())));
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contextRepository.saveContext(context, request, response);
    }
}
