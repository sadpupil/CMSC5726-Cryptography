package com.cryptograph.utils;

import com.cryptograph.aes.Aes;
import com.cryptograph.des.Des;
import com.cryptograph.idea.Idea;
import com.cryptograph.rsa.Rsa;
import com.cryptograph.tdes.Tdes;

import java.util.Base64;

public class TestFactoryUtil {

    private static TestFactoryUtil instance;
    private TestFactoryUtil() {}

    public static TestFactoryUtil getInstance() {
        if (instance == null) {
            instance = new TestFactoryUtil();
        }
        return instance;
    }

    public <T> void testCryptAlgo (T algoCore, String message) throws InterruptedException {
        if(algoCore == null) {
            return;
        }
        if(algoCore instanceof Idea idea) {
            byte[] key = idea.getIdeaKey();

            // encrypt the plaintext
            // calculate the encryption time
            long startTimeEncrypt = System.currentTimeMillis();
            byte[] cipherText = idea.encryptIdeaMsg(message, key);
            long endTimeEncrypt = System.currentTimeMillis();

            // Encode the cipher text using BASE64
            // To neatly print it in console
            String encodedStr = Base64.getEncoder().encodeToString(cipherText);


            // decrypt the cipher text
            // calculate the decryption time
            long startTimeDecrypt = System.currentTimeMillis();
            byte[] decryptedData = idea.decryptIdeaCipher(cipherText, key);
            long endTimeDecrypt = System.currentTimeMillis();

            System.out.println("Test Result of IDEA:");
            System.out.println("    The Original Message: " + message);
            System.out.println("    The Cipher Text: " + encodedStr + ", time consumed: " + (double)(endTimeEncrypt - startTimeEncrypt) + "ms");

            System.out.println("    The Message Decrypted from Cipher Text: " + new String(decryptedData) +
                    ", time consumed: " + (double)(endTimeDecrypt - startTimeDecrypt) + "ms" + '\n');
        }
        else if(algoCore instanceof Des des) {
            byte[] key = des.getDesKey();

            // encrypt the plaintext
            // calculate the encryption time
            long startTimeEncrypt = System.currentTimeMillis();
            byte[] cipherText = des.encryptDesMsg(message, key);
            long endTimeEncrypt = System.currentTimeMillis();

            // Encode the cipher text using BASE64
            // To neatly print it in console
            String encodedStr = Base64.getEncoder().encodeToString(cipherText);

            // decrypt the cipher text
            // calculate the decryption time
            long startTimeDecrypt = System.currentTimeMillis();
            byte[] decryptedData = des.decryptDesCipher(cipherText, key);
            long endTimeDecrypt = System.currentTimeMillis();

            System.out.println("Test Result of DES:");
            System.out.println("    The Original Message: " + message);
            System.out.println("    The Cipher Text: " + encodedStr + ", time consumed: " + (double)(endTimeEncrypt - startTimeEncrypt) + "ms");

            System.out.println("    The Message Decrypted from Cipher Text: " + new String(decryptedData) +
                    ", time consumed: " + (double)(endTimeDecrypt - startTimeDecrypt) + "ms" + '\n');
        }
        else if(algoCore instanceof Tdes tdes) {
            byte[] key = tdes.get3DesKey();
            // encrypt the plaintext
            // calculate the encryption time
            long startTimeEncrypt = System.currentTimeMillis();
            byte[] cipherText = tdes.encrypt3DesMsg(message, key);
            long endTimeEncrypt = System.currentTimeMillis();

            // Encode the cipher text using BASE64
            // To neatly print it in console
            String encodedStr = Base64.getEncoder().encodeToString(cipherText);

            // decrypt the cipher text
            // calculate the decryption time
            long startTimeDecrypt = System.currentTimeMillis();
            byte[] decryptedData = tdes.decrypt3DesCipher(cipherText, key);
            long endTimeDecrypt = System.currentTimeMillis();

            System.out.println("Test Result of 3DES:");
            System.out.println("Key size: " + 168);
            System.out.println("    The Original Message: " + message);
            System.out.println("    The Cipher Text: " + encodedStr + ", time consumed: " + (double)(endTimeEncrypt - startTimeEncrypt) + "ms");

            System.out.println("    The Message Decrypted from Cipher Text: " + new String(decryptedData) +
                    ", time consumed: " + (double)(endTimeDecrypt - startTimeDecrypt) + "ms" + '\n');

        }
        else if(algoCore instanceof Aes aes) {
            byte[] key = aes.getAESKey(256);
            // encrypt the plaintext
            // calculate the encryption time
            long startTimeEncrypt = System.currentTimeMillis();
            byte[] cipherText = aes.encryptAesMsg(message, key);
            long endTimeEncrypt = System.currentTimeMillis();

            // Encode the cipher text using BASE64
            // To neatly print it in console
            String encodedStr = Base64.getEncoder().encodeToString(cipherText);

            // decrypt the cipher text
            // calculate the decryption time
            long startTimeDecrypt = System.currentTimeMillis();
            byte[] decryptedData = aes.decryptAesMsg(cipherText, key);
            long endTimeDecrypt = System.currentTimeMillis();

            System.out.println("Test Result of AES:");
            System.out.println("Key size: " + 256);
            System.out.println("    The Original Message: " + message);
            System.out.println("    The Cipher Text: " + encodedStr + ", time consumed: " + (double)(endTimeEncrypt - startTimeEncrypt) + "ms");

            System.out.println("    The Message Decrypted from Cipher Text: " + new String(decryptedData) +
                    ", time consumed: " + (double)(endTimeDecrypt - startTimeDecrypt) + "ms" + '\n');
        }
        else if(algoCore instanceof Rsa rsa) {
            long startTimeEncrypt = System.currentTimeMillis();
            byte[] cipherText = rsa.encryptRsaMsg(message);
            long endTimeEncrypt = System.currentTimeMillis();

            // Encode the cipher text using BASE64
            // To neatly print it in console
            String encodedStr = Base64.getEncoder().encodeToString(cipherText);

            // decrypt the cipher text
            // calculate the decryption time
            long startTimeDecrypt = System.currentTimeMillis();
            byte[] decryptedData = rsa.decryptRsaMsg(cipherText);
            long endTimeDecrypt = System.currentTimeMillis();

            System.out.println("Test Result of RSA:");
            System.out.println("Key size: " + 2048);
            System.out.println("    The Original Message: " + message);
            System.out.println("    The Cipher Text: " + encodedStr + ", time consumed: " + (double)(endTimeEncrypt - startTimeEncrypt) + "ms");

            System.out.println("    The Message Decrypted from Cipher Text: " + new String(decryptedData) +
                    ", time consumed: " + (double)(endTimeDecrypt - startTimeDecrypt) + "ms" + '\n');
        }
    }

}
