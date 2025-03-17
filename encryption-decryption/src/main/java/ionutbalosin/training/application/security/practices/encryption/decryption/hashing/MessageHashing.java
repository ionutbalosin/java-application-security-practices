/*
 * Application Security for Java Developers
 *
 * Copyright (C) 2024 Ionut Balosin
 * Website: www.ionutbalosin.com
 * X: @ionutbalosin | LinkedIn: ionutbalosin | Mastodon: ionutbalosin@mastodon.social
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class demonstrates how to use SHA-256 to verify data integrity by comparing hash values.
 *
 * <p>Note: SHA-256 ensures data integrity but does not provide authenticity (unlike HMAC), meaning
 * an attacker can still modify data and recompute the hash.
 */
public class MessageHashing {

  public static void main(String[] args) throws Exception {
    final String originalData = "This is the original data.";
    byte[] originalHash = hashData(originalData.getBytes());

    // Simulate data transmission or storage (assume data might be modified)
    final String receivedData = "This is the original data.";
    byte[] receivedHash = hashData(receivedData.getBytes());

    // Verify data integrity by comparing hashes
    boolean isDataIntact = MessageDigest.isEqual(originalHash, receivedHash);
    System.out.printf("Is data intact: [%s]%n", isDataIntact);
  }

  // Computes the SHA-256 hash of the given data.
  public static byte[] hashData(byte[] data) throws NoSuchAlgorithmException {
    final MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return digest.digest(data);
  }
}
