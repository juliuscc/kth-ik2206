import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class SessionKey {

    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keylength);
        secretKey = keyGenerator.generateKey();
    }

    public SessionKey(String encodedkey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedkey);
        secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String encodeKey() {
        return Base64
                .getEncoder()
                .encodeToString(secretKey.getEncoded());
    }

}

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