package com.amazonaws.encryptionsdk.internal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * This API is internal and subject to change. It is used to add BouncyCastleProvider to the
 * java.security.Provider list, and to provide a static reference to BouncyCastleProvider for internal
 * classes.
 */
public class BouncyCastleConfiguration {
    static final BouncyCastleProvider INTERNAL_BOUNCY_CASTLE_PROVIDER;
    static {
        BouncyCastleProvider bouncyCastleProvider;
        try {
            bouncyCastleProvider = new BouncyCastleProvider();
            Security.addProvider(bouncyCastleProvider);
        } catch (final Throwable ex) {
            bouncyCastleProvider = null;
            // Swallow this error. We'll either succeed or fail later with reasonable
            // stacktraces.
        }
        INTERNAL_BOUNCY_CASTLE_PROVIDER = bouncyCastleProvider;
    }

    /**
     * Prevent instantiation
     */
    private BouncyCastleConfiguration() {
    }

    /**
     * No-op used to force class loading on first call, which will cause the static blocks to be executed
     */
    public static void init() {}
}
