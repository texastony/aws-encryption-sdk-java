package com.amazonaws.encryptionsdk;

import com.amazonaws.encryptionsdk.internal.StaticMasterKey;
import com.amazonaws.encryptionsdk.model.CiphertextHeaders;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.spy;

public class ParsedCiphertextTest extends CiphertextHeaders {
    final byte[] ciphertext_ = {0};

    final int byteSize = 0;
    final int frameSize = 0;

    private StaticMasterKey masterKeyProvider;
    private AwsCrypto encryptionClient_;

    @Before
    public void init() {
        masterKeyProvider = spy(new StaticMasterKey("testmaterial"));

        encryptionClient_ = new AwsCrypto();
        encryptionClient_.setEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256);
    }

    @Test
    public void completeCiphertext() {
        final byte[] plaintextBytes = new byte[byteSize];

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC1", "ParsedCiphertext test with %d" + byteSize);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        final byte[] cipherText = encryptionClient_.encryptData(
                masterKeyProvider,
                plaintextBytes,
                encryptionContext).getResult();
        ParsedCiphertext pCt = new ParsedCiphertext(cipherText);
    }

    @Test(expected = BadCiphertextException.class)
    public void incompleteCiphertext() {
        ParsedCiphertext pCt = new ParsedCiphertext(ciphertext_);
    }
}
