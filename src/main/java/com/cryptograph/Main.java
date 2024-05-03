package com.cryptograph;

import com.cryptograph.aes.Aes;
import com.cryptograph.des.Des;
import com.cryptograph.idea.Idea;
import com.cryptograph.rsa.Rsa;
import com.cryptograph.tdes.Tdes;
import com.cryptograph.utils.TestFactoryUtil;

public class Main {

    public static void main(String[] args) throws InterruptedException {

        // Message that's going to be encrypted
        String message = "My name is CHEN Yujing. I'm enrolled in CMSC5726.";

        Idea ideaObject = new Idea();
        Des desObject = new Des();
        Tdes tdesObject = new Tdes();
        Aes aesObject = new Aes();
        Rsa rsaObject = new Rsa();
        TestFactoryUtil testFactoryUtil = TestFactoryUtil.getInstance();

        // Carry out the tests using different algorithms
        // DES
        testFactoryUtil.testCryptAlgo(desObject, message);
        // 3DES
        testFactoryUtil.testCryptAlgo(tdesObject, message);
        // AES
        testFactoryUtil.testCryptAlgo(aesObject, message);
        // RSA
        testFactoryUtil.testCryptAlgo(rsaObject, message);
        // IDEA
        testFactoryUtil.testCryptAlgo(ideaObject, message);
    }

}
