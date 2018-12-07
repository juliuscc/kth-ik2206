import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(ciphertext);
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, CertificateException {
        X509Certificate certificate = getCertificate(certfile);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Path path = Paths.get(keyfile);
        byte[] privKeyByteArray = Files.readAllBytes(path);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Copied from: https://docs.oracle.com/javase/7/docs/api/java/security/cert/X509Certificate.html
     */
    public static X509Certificate getCertificate(String certificateFilePath) throws IOException, CertificateException {
        X509Certificate cert;
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(certificateFilePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
        return cert;
    }
}
