package com.cryptograph.tdes;

import com.cryptograph.utils.SecurityProviderUtil;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Tdes {

    public static final String ALGORITHM_TYPE = "DESede";
    public static final String CIPHER_STANDARD = "DESede/ECB/PKCS5Padding";

    public static Cipher cipher;

    static {
        try {
            cipher = Cipher.getInstance(CIPHER_STANDARD);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for generating 3DES key
     * Can use different key size to initialize (112 or 168)
     * @return
     */
    public byte[] get3DesKey (){
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_TYPE, "BC");
            keyGenerator.getProvider();
            // keyGenerator.init(keySize);
            keyGenerator.init(168);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method for encrypting the message using 3DES
     * @param message
     * @param key
     * @return
     */
    public byte[] encrypt3DesMsg(String message, byte[] key) {
        try {

            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

            Security.addProvider(SecurityProviderUtil.PROVIDER);

            // convert the key
            DESedeKeySpec desedeKeySpec = new DESedeKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_TYPE);
            Key convertedKey = factory.generateSecret(desedeKeySpec);

            cipher.init(Cipher.ENCRYPT_MODE, convertedKey);
            return cipher.doFinal(plaintext);

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt3DesCipher(byte[] cipherText, byte[] key) {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);

            // convert the key
            DESedeKeySpec desedeKeySpec = new DESedeKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_TYPE);
            Key convertedKey = factory.generateSecret(desedeKeySpec);

            cipher.init(Cipher.DECRYPT_MODE, convertedKey);
            return cipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
