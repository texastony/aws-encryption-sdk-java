// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;


public class CustomHeaderExampleSdkV1 {
  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  public static void main(final String[] args) {
    final String keyId = args[0];
    final Regions region = Regions.fromName(args[1]);
    encryptAndDecryptStaticHeaderValues(keyId, region);
    encryptAndDecryptHeaderDynamicOnEncryptionContext(keyId);
  }


  // The Dynamic approach allows the Custom Header Values to be
  // injected post the encrypt/decrypt call site,
  // potentially re-using a KMS Client (HTTPS Client) for multiple
  // tenants.
  // However, it REQUIRES that the Values can be determined solely on
  // the information in the KMS requests.
  static void encryptAndDecryptHeaderDynamicOnEncryptionContext(final String keyId) {
    final AwsCrypto crypto = AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();
    CustomHeaderRequestHandler customHeaderRequestHandler = new CustomHeaderRequestHandler();
    final AWSKMSClientBuilder kmsClient = AWSKMSClientBuilder.standard()
            .withRequestHandlers(customHeaderRequestHandler);
    // Use `withClientBuilder` to customize the KMS Client,
    final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder()
            .withClientBuilder(kmsClient)
            .buildStrict(keyId);

    genericESDKEncryptDecrypt(crypto, keyProvider);
  }

  // The Static Header Value approach allows for the header values
  // to be determined by all the context present at the encrypt/decrypt
  // call site.
  // Unfortunately, this approach requires an HTTPS client
  // per Custom Header Value Set.
  // Creating HTTPS clients is expensive,
  // so it would be best to cache the KmsMasterKeyProvider
  // created in this manner and re-use them.
  // However, this cache SHOULD have a TTL,
  // as your hosts can only have so many HTTPS clients
  // alive at a time.
  // (That limit can be increased by increasing the OSes File Descriptor Limit...
  // I believe...)
  static void encryptAndDecryptStaticHeaderValues(
          final String keyId,
          final Regions region) {
    final AwsCrypto crypto = AwsCrypto.builder()
            .withCommitmentPolicy(CommitmentPolicy.RequireEncryptRequireDecrypt)
            .build();
    ClientConfiguration clientConfig = new ClientConfiguration();
    // Using `ClientConfiguration#withHeader` will only work for static values.
    clientConfig.withUserAgentPrefix("Tony  ");
    clientConfig.withUserAgentSuffix("  Tony");
    clientConfig.withHeader("x-amz-source-Arn", "tony");
    clientConfig.withHeader("x-amz-source-source-Account", "827585335069");
    clientConfig.withHeader("x-amz-user-agent", "Tony");
    clientConfig.withHeader("x-amz-user-Agent", "Tony");
    clientConfig.withHeader("User-Agent", "Tony");
    clientConfig.withHeader("X-Amz-User-Agent", "Tony");
    final AWSKMS kmsClient = AWSKMSClientBuilder.standard()
            .withClientConfiguration(clientConfig).withRegion(region).build();
    // Use `withCustomClientFactory` to customize the KMS Client.
    // For the static case,
    // this maybe more memory efficient than using `withClientBuilder`,
    // as it by-passes the ESDK's Client cache,
    // allowing the application to maintain control its' own KMS client allocations.
    // See ESDK Client Cache:
    // https://github.com/aws/aws-encryption-sdk-java/blob/master/src/main/java/com/amazonaws/encryptionsdk/kms/KmsMasterKeyProvider.java#L299
    final KmsMasterKeyProvider keyProvider = KmsMasterKeyProvider.builder()
            .withCustomClientFactory(regionName -> {
              if (regionName.equals(region.getName())) {
                return kmsClient;
              } else {
                throw new RuntimeException(String.format(
                        "The only supported region is: %s", region.getName()));
              }
            })
            .buildStrict(keyId);

    genericESDKEncryptDecrypt(crypto, keyProvider);
  }

  public static class CustomHeaderRequestHandler extends RequestHandler2 {
    public AmazonWebServiceRequest beforeExecution(AmazonWebServiceRequest request) {
      Map<String, String> encryptionContext = null;
      if (request instanceof GenerateDataKeyRequest) {
        GenerateDataKeyRequest generateRequest = (GenerateDataKeyRequest) request;
        encryptionContext = generateRequest.getEncryptionContext();
      } else if (request instanceof DecryptRequest) {
        DecryptRequest decryptRequest = (DecryptRequest) request;
        encryptionContext = decryptRequest.getEncryptionContext();
      } else if (request instanceof EncryptRequest) {
        EncryptRequest encryptRequest = (EncryptRequest) request;
        encryptionContext = encryptRequest.getEncryptionContext();
      }
      if (Objects.nonNull(encryptionContext)) {
        // Here, you would fork on the encryptionContext,
        // which I assume is unique to each to Custom Header Set you need.
        // If the encryptionContext is NOT enough information to determine the header values,
        // you must use the Static Approach.
        request.putCustomRequestHeader("x-amz-source-Arn", "tony");
        request.putCustomRequestHeader("x-amz-source-source-Account", "827585335069");
      }
      return request;
    }
  }

  private static void genericESDKEncryptDecrypt(AwsCrypto crypto, KmsMasterKeyProvider keyProvider) {
    final Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(keyProvider, EXAMPLE_DATA, encryptionContext);
    final byte[] ciphertext = encryptResult.getResult();
    final CryptoResult<byte[], KmsMasterKey> decryptResult = crypto.decryptData(keyProvider, ciphertext);
    if (!encryptionContext.entrySet().stream()
            .allMatch(e -> e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey())))) {
      throw new IllegalStateException("Wrong Encryption Context!");
    }
    assert Arrays.equals(decryptResult.getResult(), EXAMPLE_DATA);
  }
}
