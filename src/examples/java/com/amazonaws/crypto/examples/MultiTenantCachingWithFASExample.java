// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import javax.annotation.Nonnull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


public class MultiTenantCachingWithFASExample {
    private static final int MAX_CACHED_DATA_KEYS = 500;
    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    private static final SdkHttpClient singletonHttpClient = ApacheHttpClient.create();
    private static final LocalCryptoMaterialsCache singletonLocalCryptoMaterialsCache = new LocalCryptoMaterialsCache(MAX_CACHED_DATA_KEYS);
    private static final AwsCrypto crypto = AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    public static void main(final String[] args) {
        final String keyName = args[0];
        final String tenantId = args.length > 1 ? args[1] : UUID.randomUUID().toString();
        final String sourceArn = args.length > 2 ? args[2] : "arn:aws:iam::827585335069:role/FreeRTOS";
        final String sourceAccount = args.length > 3 ? args[3] : "827585335069";
        final String fasToken = "";
        encryptAndDecrypt(keyName, tenantId, sourceArn, sourceAccount, fasToken);
    }

    static AwsCredentialsProvider credentialsFromFASToken(final String fasToken) {
        // Replace with FAS Credential look up:
        return DefaultCredentialsProvider.builder().build();
    }

    static void encryptAndDecrypt(
            @Nonnull final String keyName,
            @Nonnull final String tenantId,
            @Nonnull final String sourceArn,
            @Nonnull final String sourceAccount,
            @Nonnull final String fasToken
    ) {
        final KmsClientBuilder kmsClient = KmsClient.builder()
                .httpClient(singletonHttpClient)
                .credentialsProvider(credentialsFromFASToken(fasToken))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        // Proper FAS token headers go here
                        .putHeader("x-amz-source-Arn", sourceArn)
                        .putHeader("x-amz-source-Account", sourceAccount)
                        .build());
        // Use `builderSupplier` to customize the KMS Client,
        final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder()
                .builderSupplier(() -> kmsClient)
                .buildStrict(keyName);
        final CachingCryptoMaterialsManager cachingCMM = CachingCryptoMaterialsManager.newBuilder()
                .withCache(singletonLocalCryptoMaterialsCache)
                .withMaxAge(15L, TimeUnit.MINUTES)
                .withPartitionId(tenantId)
                .withMasterKeyProvider(keyProvider)
                .build();

        final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
        CryptoResult<byte[], ?> cryptoResult = crypto.encryptData(cachingCMM, EXAMPLE_DATA, encryptionContext);
        final byte[] ciphertext = cryptoResult.getResult();

        final CryptoResult<byte[], ?> decryptResult = crypto.decryptData(cachingCMM, ciphertext);

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
