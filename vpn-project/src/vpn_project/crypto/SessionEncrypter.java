package vpn_project.crypto;

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

    public SessionEncrypter(String key, String iv) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");

        this.key = new SessionKey(key);
        this.iv = new IvParameterSpec(Base64.getDecoder().decode(iv));

        cipher.init(Cipher.ENCRYPT_MODE, this.key.getSecretKey(), this.iv);
    }

    public SessionEncrypter(Integer keylength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        cipher = Cipher.getInstance("AES/CTR/NoPadding");

        key = new SessionKey(keylength);

        SecureRandom rnd = new SecureRandom();
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        rnd.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), iv);
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

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output, cipher);
    }
}
