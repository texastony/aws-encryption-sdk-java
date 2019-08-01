package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import org.junit.Test;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;

public class ParsedCiphertextTest extends CiphertextHeaders {
    final byte[] ciphertext_ = {0};

    @Test(expected = BadCiphertextException.class)
    public void incompleteCiphertext() {
        ParsedCiphertext parsedCiphertext = new ParsedCiphertext(ciphertext_);
    }
}
