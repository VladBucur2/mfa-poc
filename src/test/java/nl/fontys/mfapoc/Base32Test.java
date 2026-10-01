package nl.fontys.mfapoc;

import nl.fontys.mfapoc.service.Base32;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Base32Test {

    @Test
    @DisplayName("matches the RFC 4648 test vectors, without padding")
    void matchesRfcVectors() {
        assertEquals("MY", encode("f"));
        assertEquals("MZXQ", encode("fo"));
        assertEquals("MZXW6", encode("foo"));
        assertEquals("MZXW6YQ", encode("foob"));
        assertEquals("MZXW6YTB", encode("fooba"));
        assertEquals("MZXW6YTBOI", encode("foobar"));
    }

    @Test
    @DisplayName("decodes padded input as produced by other tools")
    void decodesPadded() {
        assertArrayEquals("foobar".getBytes(StandardCharsets.US_ASCII),
                Base32.decode("MZXW6YTBOI======"));
    }

    @Test
    @DisplayName("round-trips random secrets")
    void roundTripsRandomBytes() {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 50; i++) {
            byte[] raw = new byte[20];
            random.nextBytes(raw);
            assertArrayEquals(raw, Base32.decode(Base32.encode(raw)), Arrays.toString(raw));
        }
    }

    private String encode(String text) {
        return Base32.encode(text.getBytes(StandardCharsets.US_ASCII));
    }
}
