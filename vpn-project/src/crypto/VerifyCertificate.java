package crypto;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class VerifyCertificate {
    public static void main(String[] args) throws IOException, CertificateException {
        if (args.length < 2) {
            System.exit(-1);
        }

        String caFilePath = args[0];
        String userFilePath = args[1];

        X509Certificate caCert = CertificateCrypto.getCertificateFromFile(caFilePath);
        X509Certificate userCert = CertificateCrypto.getCertificateFromFile(userFilePath);

        System.out.println(caCert.getSubjectDN());
        System.out.println(userCert.getSubjectDN());

        try {
            caCert.verify(caCert.getPublicKey());
            userCert.verify(caCert.getPublicKey());
            userCert.checkValidity(new Date());
            System.out.println("Pass");
        } catch (Exception e) {
            System.out.println("Fail");
            System.out.println(e.getMessage());
        }
    }
}

