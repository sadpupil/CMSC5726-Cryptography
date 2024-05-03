package com.cryptograph.idea;

import com.cryptograph.utils.SecurityProviderUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Idea {

    public static final String ALGORITHM_TYPE = "IDEA";
    public static final String CIPHER_STANDARD = "IDEA/ECB/ISO10126Padding";

    /**
     * Method for generating IDEA Key
     * @return
     */
    public byte[] getIdeaKey() {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            // initialize IDEA key using 128 bits
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_TYPE);
            keyGenerator.init(128);
            // generate keys
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for encrypting the message using IDEA
     * @param key
     * @return
     */
    public byte[] encryptIdeaMsg(String message, byte[] key) {
        try {
            // convert the message to a plaintext of bits
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_TYPE);
            Cipher cipher = Cipher.getInstance(CIPHER_STANDARD);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for decrypting the cipher text
     * @param cipherText
     * @param key
     * @return
     */
    public byte[] decryptIdeaCipher(byte[] cipherText, byte[] key) {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM_TYPE);
            Cipher cipher = Cipher.getInstance(CIPHER_STANDARD);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(cipherText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
