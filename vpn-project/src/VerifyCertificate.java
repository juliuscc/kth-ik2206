import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class VerifyCertificate {
    public static void main(String[] args) throws IOException, CertificateException {
        if (args.length < 2) {
            System.exit(-1);
        }

        String caFilePath = args[0];
        String userFilePath = args[1];

        X509Certificate caCert = getCertificate(caFilePath);
        X509Certificate userCert = getCertificate(userFilePath);

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


    /**
     * Copied from: https://docs.oracle.com/javase/7/docs/api/java/security/cert/X509Certificate.html
     */
    private static X509Certificate getCertificate(String certificateFilePath) throws IOException, CertificateException {
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

