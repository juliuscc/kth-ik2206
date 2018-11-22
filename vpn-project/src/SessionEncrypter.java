import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.*;
import java.util.Base64;

public class SessionEncrypter {

    private Cipher cipher;
    private SessionKey key;
    private IvParameterSpec iv;

    public SessionEncrypter(Integer keylength) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {

        cipher = Cipher.getInstance("AES/CTR/NoPadding");

        key = new SessionKey(keylength);

        SecureRandom rnd = new SecureRandom();
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        rnd.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public String encodeKey() {
        return key.encodeKey();
    }

    public String encodeIV() {
        return Base64
                .getEncoder()
                .withoutPadding()
                .encodeToString(iv.getIV());
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) throws InvalidAlgorithmParameterException, InvalidKeyException {
        cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), iv);
        return new CipherOutputStream(output, cipher);
    }
}
