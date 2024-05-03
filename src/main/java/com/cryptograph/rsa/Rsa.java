package com.cryptograph.rsa;

import com.cryptograph.utils.SecurityProviderUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Rsa {

    public static final String ALGORITHM_TYPE = "RSA";
    public static final String CIPHER_STANDARD = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";

    public static Cipher cipher;
    // Generator for the public key and private key of RSA
    public static KeyPairGenerator keyPairGenerator;
    public static PublicKey publicKey;
    public static PrivateKey privateKey;

    static {
        try {
            cipher = Cipher.getInstance(CIPHER_STANDARD);
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_TYPE);
            // Length of key is 1024
            // RSA-1024
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            // generate the public and the private key
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Use the public key to encrypt the message
     * @param message
     * @return
     */
    public byte[] encryptRsaMsg(String message) {
        try {
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            // use the public key to encrypt the message
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext);
        } catch (InvalidKeyException |  IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Uuse the private key to decrypt the cipher text
     * @param cipherText
     * @return
     */
    public byte[] decryptRsaMsg(byte[] cipherText) {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherText);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
