/*
 * Application Security for Java Developers
 *
 * Copyright (C) 2025 Ionut Balosin
 * Website:      www.ionutbalosin.com
 * Social Media:
 *   LinkedIn:   ionutbalosin
 *   Bluesky:    @ionutbalosin.bsky.social
 *   X:          @ionutbalosin
 *   Mastodon:   ionutbalosin@mastodon.social
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package ionutbalosin.training.application.security.practices.encryption.decryption.hashing;

import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Demonstrates HMAC-SHA256 for data integrity and authenticity using a secure key.
 *
 * <p>This approach is commonly used in scenarios such as verifying JSON Web Tokens (JWT). When an
 * Identity Provider (IdP) issues a JWT, it signs the token using HMAC-SHA256. Later, when the token
 * is received (either for introspection or via JWKS), the IdP checks its integrity and authenticity
 * by verifying the signature using the same secret key that was initially used to sign it.
 */
public class HmacMessageAuthenticator {

  public static void main(String[] args) throws Exception {
    final SecretKey secretKey = generateHmacKey();
    final String originalData = "This is the original data.";

    // Generate HMAC for the original data
    final byte[] originalHmac = generateHMAC(originalData.getBytes(), secretKey);

    // Simulate data transmission or storage (assume data might be modified)
    final String receivedData = "This is the original data.";
    final byte[] receivedHmac = generateHMAC(receivedData.getBytes(), secretKey);

    // Verify data authenticity
    final boolean isAuthentic = Arrays.equals(originalHmac, receivedHmac);
    System.out.printf("Is data authentic: [%s]%n", isAuthentic);
  }

  // Generates a secure random key for HMAC-SHA256.
  public static SecretKey generateHmacKey() throws Exception {
    final KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
    return keyGen.generateKey();
  }

  // Computes the HMAC-SHA256 of the given data using a secure secret key.
  public static byte[] generateHMAC(byte[] data, SecretKey key) throws Exception {
    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(key);
    return mac.doFinal(data);
  }
}
