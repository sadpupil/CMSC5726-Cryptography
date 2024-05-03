package com.cryptograph.aes;

import com.cryptograph.utils.SecurityProviderUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Aes {

    public static final String ALGORITHM_TYPE = "AES";
    public static final String CIPHER_STANDARD = "AES/ECB/PKCS5Padding";

    public static Cipher cipher;

    static {
        try {
            cipher = Cipher.getInstance(CIPHER_STANDARD);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getAESKey(int keySize) {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_TYPE, "BC");
            keyGenerator.init(keySize);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptAesMsg(String message, byte[] key) {
        try {
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            Security.addProvider(SecurityProviderUtil.PROVIDER);

            Key convertedKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, convertedKey);
            return cipher.doFinal(plaintext);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decryptAesMsg(byte[] cipherText, byte[] key) {
        try {
            Security.addProvider(SecurityProviderUtil.PROVIDER);
            Key convertedKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, convertedKey);
            return cipher.doFinal(cipherText);
        }  catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
