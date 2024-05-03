package com.cryptograph.des;

import com.cryptograph.utils.SecurityProviderUtil;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

public class Des {

    public static final String ALGORITHM_TYPE = "DES";
    public static final String CIPHER_STANDARD = "DES/ECB/PKCS5Padding";

    // Functional Cryptographic System
    public static Cipher cipher;

    static {
        try {
            cipher = Cipher.getInstance(CIPHER_STANDARD);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for generating DES key
     * @return
     */
    public byte[] getDesKey() {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            // initialize DES key using 56 bits
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_TYPE);
            keyGenerator.init(56);
            // generate keys
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for encrypting the message using DES
     * @param message
     * @param key
     * @return
     */
    public byte[] encryptDesMsg(String message, byte[] key) {
        try {

            // convert the message to a plaintext of bits
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

            Security.addProvider(SecurityProviderUtil.PROVIDER);

            // convert the key
            DESKeySpec desKeySpec = new DESKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_TYPE);
            Key convertedKey = factory.generateSecret(desKeySpec);

            cipher.init(Cipher.ENCRYPT_MODE, convertedKey);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Message for decrypting the cipher text using DES
     * @param cipherText
     * @param key
     * @return
     */
    public byte[] decryptDesCipher(byte[] cipherText, byte[] key) {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);

            // convert the key
            DESKeySpec desKeySpec = new DESKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_TYPE);
            Key convertedKey = factory.generateSecret(desKeySpec);

            cipher.init(Cipher.DECRYPT_MODE, convertedKey);
            return cipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
