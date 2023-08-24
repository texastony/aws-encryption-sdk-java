package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.Test;
import software.amazon.awssdk.regions.Region;

public class CustomHeaderExampleTest {

  @Test
  public void testEncryptAndDecrypt() {
    CustomHeaderExample.encryptAndDecrypt(
            KMSTestFixtures.US_WEST_2_KEY_ID,
            Region.US_WEST_2);
  }
}
