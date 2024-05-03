package com.cryptograph.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public class SecurityProviderUtil {

    // register the algorithm provider component in a global scale
    public static final Provider PROVIDER = new BouncyCastleProvider();

    static {
        // use BouncyCastle as the implementation of Algorithms
        Security.addProvider(PROVIDER);
    }

}
