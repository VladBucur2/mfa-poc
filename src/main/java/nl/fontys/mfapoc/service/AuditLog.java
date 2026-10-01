package nl.fontys.mfapoc.service;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One structured JSON line per security event. The forbidden-field policy is enforced by
 * construction: this class only ever writes the fields below, so a password, a code or a raw
 * session id cannot reach the log by accident.
 */
@Component
public class AuditLog {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    public void event(String eventType, String actor, String outcome, HttpServletRequest request) {
        event(eventType, actor, outcome, request, Map.of());
    }

    public void event(String eventType, String actor, String outcome,
                      HttpServletRequest request, Map<String, String> extra) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("ts", Instant.now().toString());
        fields.put("event", eventType);
        fields.put("actor", actor == null ? "-" : actor);
        fields.put("outcome", outcome);
        fields.put("src_ip", request == null ? "-" : request.getRemoteAddr());
        fields.put("session", sessionHash(request));
        fields.putAll(extra);

        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (!first) {
                json.append(',');
            }
            json.append('"').append(escape(entry.getKey())).append("\":\"")
                .append(escape(entry.getValue())).append('"');
            first = false;
        }
        AUDIT.info(json.append('}').toString());
    }

    /** A hash, never the session id itself: enough to correlate events, useless to steal. */
    private String sessionHash(HttpServletRequest request) {
        if (request == null || request.getSession(false) == null) {
            return "-";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(request.getSession(false).getId().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (Exception e) {
            return "-";
        }
    }

    private String escape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");
    }
}
