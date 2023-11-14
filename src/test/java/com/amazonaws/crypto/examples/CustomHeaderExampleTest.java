package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import com.amazonaws.regions.Regions;
import org.junit.Test;

public class CustomHeaderExampleTest {

  @Test
  public void testEncryptAndDecryptV2() {
    CustomHeaderExampleSdkV2.encryptAndDecrypt(
            KMSTestFixtures.US_WEST_2_KEY_ID
    );
  }

  @Test
  public void testEncryptAndDecryptV1Static() {
    CustomHeaderExampleSdkV1.encryptAndDecryptStaticHeaderValues(
            KMSTestFixtures.US_WEST_2_KEY_ID,
            Regions.US_WEST_2
    );
  }

  @Test
  public void testEncryptAndDecryptV1Dynamic() {
    CustomHeaderExampleSdkV1.encryptAndDecryptHeaderDynamicOnEncryptionContext(
            KMSTestFixtures.US_WEST_2_KEY_ID
    );
  }
}
