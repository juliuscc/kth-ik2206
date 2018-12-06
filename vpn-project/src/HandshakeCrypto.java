import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    public static byte[] encrypt(byte[] plaintext, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) {
        try {
            X509Certificate certificate = VerifyCertificate.getCertificate(certfile);
            return certificate.getPublicKey();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) {
        try {
            Path path = Paths.get(keyfile);
            byte[] privKeyByteArray = Files.readAllBytes(path);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
}
