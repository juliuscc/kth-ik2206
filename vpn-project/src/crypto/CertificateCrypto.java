package crypto;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CertificateCrypto {

    private X509Certificate certificate;

    public CertificateCrypto(String certificateData) throws IOException, CertificateException {
        certificate = getCertificateFromByte64String(certificateData);
    }

    public CertificateCrypto(boolean readFromFile, String certificateData) throws IOException, CertificateException {
        if (readFromFile) {
            certificate = getCertificateFromFile(certificateData);
        } else {
            certificate = getCertificateFromByte64String(certificateData);
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String encodeCertificate() throws CertificateEncodingException {
        return Base64
                .getEncoder()
                .withoutPadding()
                .encodeToString(certificate.getEncoded());
    }

    /**
     * Copied from: https://docs.oracle.com/javase/7/docs/api/java/security/cert/X509Certificate.html
     */
    public static X509Certificate getCertificateFromFile(String certificateFilePath) throws IOException, CertificateException {
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

    /**
     * Copied from: https://stackoverflow.com/a/20137303
     */
    public static X509Certificate getCertificateFromByte64String(String certificateData) throws CertificateException {
        X509Certificate certificate;

        byte[] decodedCertificateData = Base64.getDecoder().decode(certificateData);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificateData));

        return certificate;
    }

    public static PrivateKey getPrivateKeyFromFile(String keyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyFilePath);
        byte[] privKeyByteArray = Files.readAllBytes(path);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }
}
