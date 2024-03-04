// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;

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


public class ESDK_Java_SDKV2_CachingCMM_SourceArn_SourceAccount_Header_Example {
    private static final int MAX_CACHED_DATA_KEYS = 500;
    private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

    // You customize the request headers used with the KMS Client,
    // but all the KMS clients can probably use the same HTTP connection pool,
    // right?
    private static final SdkHttpClient singletonHttpClient = ApacheHttpClient.create();
    // This one cache is going to be used by all the cachingCMMs
    private static final LocalCryptoMaterialsCache singletonLocalCryptoMaterialsCache = new LocalCryptoMaterialsCache(MAX_CACHED_DATA_KEYS);
    private static final AwsCrypto crypto = AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();

    public static void main(final String[] args) {
        final String keyArn = args[0];
        // A UUID could work for a tenant ID, but you would want to persist the mapping of Customer to Tenant ID somewhere.
        // Ideally, your Tenant ID formula can identify the correct tenant ID based only on information included in a service request.
        // That way, you do not need to preform a look-up.
        // The Tenant ID logic SHOULD BE part of your Confused Deputy Mitigation;
        // your Service's Threat Model SHOULD include Confused Deputy as a threat.
        // An example edge case:
        // Tenant ID generation logic is deterministic on only the AWS Account ID;
        // but the AWS Account has two different resources with the service.
        // Is it OK to share a data key across these two resources?
        final String tenantId = args.length > 1 ? args[1] : UUID.randomUUID().toString();
        final String sourceArn = args.length > 2 ? args[2] : "arn:aws:iam::827585335069:role/FreeRTOS";
        final String sourceAccount = args.length > 3 ? args[3] : "827585335069";
        encryptAndDecrypt(keyArn, tenantId, sourceArn, sourceAccount);
    }


    static void encryptAndDecrypt(
            @Nonnull final String keyArn,
            // Pick something logical for the tenant ID.
            //
            @Nonnull final String tenantId,
            @Nonnull final String sourceArn,
            @Nonnull final String sourceAccount) {
        final KmsClientBuilder kmsClient = KmsClient.builder()
                .httpClient(singletonHttpClient)
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        // Set your headers here
                        .putHeader("x-amz-source-Arn", sourceArn)
                        .putHeader("x-amz-source-Account", sourceAccount)
                        .build());
        // Use `builderSupplier` to customize the KMS Client,
        final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder()
                .builderSupplier(() -> kmsClient)
                .buildStrict(keyArn);
        // You should question whether you want to bother with a Cache at all.
        // If a Tenant's requests are spread among your fleet,
        // what are the odds the same tenant hits the same host in a TTL?
        // Some Performance testing can answer this.
        // If you don't bother with caching, you can throw out the tenant ID logic.
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

        if (!encryptionContext.entrySet().stream()
                .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
            throw new IllegalStateException("Wrong Encryption Context!");
        }
        assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
    }
}
