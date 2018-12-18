package vpn_project.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {

    private Cipher cipher;
    private SessionKey key;
    private IvParameterSpec iv;

    public SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");

        this.key = new SessionKey(key);
        this.iv = new IvParameterSpec(Base64.getDecoder().decode(iv));

        cipher.init(Cipher.DECRYPT_MODE, this.key.getSecretKey(), this.iv);
    }

    public CipherInputStream openCipherInputStream(InputStream input) {
        return new CipherInputStream(input, cipher);
    }
}
