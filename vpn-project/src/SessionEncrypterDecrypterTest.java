import org.junit.jupiter.api.Test;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import java.io.*;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.*;


// THIS FILE DOES NOT WORK!
class SessionEncrypterDecrypterTest {

    @Test
    void encryptAndDecryptTest() throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {

        Integer KEYLENGTH = 128;
        String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed scelerisque.";

        // Encrypt
        SessionEncrypter sessionEncrypter = new SessionEncrypter(KEYLENGTH);
        ByteArrayOutputStream plainOutputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = sessionEncrypter.openCipherOutputStream(plainOutputStream);

        cipherOutputStream.write(input.getBytes());


        // Get cipher
        String cipher = new String(plainOutputStream.toByteArray());
        System.out.println(cipher);


        // Decrypt
        SessionDecrypter sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(), sessionEncrypter.encodeIV());
        ByteArrayInputStream plainInputStream = new ByteArrayInputStream(cipher.getBytes());
        CipherInputStream cipherInputStream = sessionDecrypter.openCipherInputStream(plainInputStream);


        ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream();
        int b;
        while ((b = cipherInputStream.read()) != -1) {
            decryptedOutputStream.write(b);
        }

        // Compare input to output
        String output = new String(decryptedOutputStream.toByteArray());

        assertEquals(input, output);
    }
}