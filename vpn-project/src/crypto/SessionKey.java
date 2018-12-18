package crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
                .withoutPadding()
                .encodeToString(secretKey.getEncoded());
    }

}