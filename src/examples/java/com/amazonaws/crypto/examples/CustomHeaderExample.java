// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKey;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;

import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;


public class CustomHeaderExample {

    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    public static void main(final String[] args) {
        final String keyName = args[0];
        final Region region = Region.of(args[1]);

        encryptAndDecrypt(keyName, region);
    }

    static void encryptAndDecrypt(final String keyName, final Region region) {
        final AwsCrypto crypto = AwsCrypto.builder()
                .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
                .build();
        // Using an `ClientOverrideConfiguration.Builder#putHeader` will only work for static values.
        final KmsClient kmsClient = KmsClient.builder().region(region)
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .putHeader("x-amz-source-Arn", "arn:aws:iam::370957321024:role/GitHub-CI-MPL-Dafny-Role-us-west-2")
                        .putHeader("x-amz-source-source-Account", "658956600833")
                        .build()).build();
        // Use and abuse the `RegionalClientSupplier` to customize the KMS Client,
        final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder()
                .customRegionalClientSupplier(cmkRegion -> {
                    if(cmkRegion.equals(region)) {
                        // return the previously built AWS KMS client so that we do
                        // not create a new client on every decrypt call.
                        return kmsClient;
                    }

                    throw new AwsCryptoException("Only " + region.id() + " is supported");
                })
                .buildStrict(keyName);

        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

        final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(keyProvider, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = encryptResult.getResult();

        final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(keyProvider, ciphertext);

        // Verify that the encryption context in the result contains the
        // encryption context supplied to the encryptData method. Because the
        // SDK can add values to the encryption context, don't require that
        // the entire context matches.
        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }

        // 10. Verify that the decrypted plaintext matches the original plaintext
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
