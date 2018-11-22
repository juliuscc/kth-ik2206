import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class SessionKeyTest {

    @Test
    void testRandomness() throws NoSuchAlgorithmException {
        SessionKey s1 = new SessionKey(256);
        SessionKey s2 = new SessionKey(256);
        SessionKey s3 = new SessionKey(256);

        assertNotEquals(s1.encodeKey(), s2.encodeKey());
        assertNotEquals(s2.encodeKey(), s3.encodeKey());
        assertNotEquals(s3.encodeKey(), s1.encodeKey());
    }

    @Test
    void encodeAndDecodeKey() throws NoSuchAlgorithmException {
        SessionKey s1 = new SessionKey(256);
        SessionKey s2 = new SessionKey(s1.encodeKey());

        assertEquals(s1.getSecretKey(), s2.getSecretKey());
    }

    @Test
    void correctKeyLength() throws NoSuchAlgorithmException {
        SessionKey s128 = new SessionKey(128);
        SessionKey s192 = new SessionKey(192);
        SessionKey s256 = new SessionKey(256);

        assertEquals(s128.getSecretKey().getEncoded().length * 8, 128);
        assertEquals(s192.getSecretKey().getEncoded().length * 8, 192);
        assertEquals(s256.getSecretKey().getEncoded().length * 8, 256);

        System.out.println("128 bit key: " + s128.encodeKey());
        System.out.println("192 bit key: " + s192.encodeKey());
        System.out.println("256 bit key: " + s256.encodeKey());
    }
}