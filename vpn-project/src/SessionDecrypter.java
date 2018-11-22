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

    public SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");

        this.key = new SessionKey(key);
        this.iv = new IvParameterSpec(Base64.getDecoder().decode(iv));
    }

    public CipherInputStream openCipherInputStream(InputStream input) throws InvalidAlgorithmParameterException, InvalidKeyException {
        cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), iv);
        return new CipherInputStream(input, cipher);
    }
}
