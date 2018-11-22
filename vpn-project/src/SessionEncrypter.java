import javax.crypto.CipherOutputStream;
import java.io.OutputStream;

public class SessionEncrypter {

    private SessionKey key;

    public SessionEncrypter(Integer keylength) {
        key = new SessionKey(keylength);
    }

    public String encodeKey() {
        return key.encodeKey();
    }

    public String encodeIV() {
        // TODO
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        // TODO 
    }
}
