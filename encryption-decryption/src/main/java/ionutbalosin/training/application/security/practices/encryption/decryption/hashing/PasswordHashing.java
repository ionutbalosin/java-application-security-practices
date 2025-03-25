/*
 * Application Security for Java Developers
 *
 * Copyright (C) 2025 Ionut Balosin
 * Website: www.ionutbalosin.com
 * Social Media:
 *   LinkedIn: ionutbalosin
 *   Bluesky: @ionutbalosin.bsky.social
 *   X: @ionutbalosin
 *   Mastodon: ionutbalosin@mastodon.social
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

import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * This class, Argon2Hashing, demonstrates how to generate a secure hash using the Argon2 algorithm.
 * It includes methods to generate a random salt and to hash a password with specified parameters
 * such as iterations, memory cost, parallelism, and hash length. The main method prints the
 * generated salt and hash in base64 encoding.
 */
public class PasswordHashing {

  private static final String PASSWORD = "My-Super-Secret-Password";
  private static final int SALT_LENGTH = 16; // Length of the salt in bytes
  private static final int ITERATIONS = 3; // Number of iterations
  private static final int MEMORY = 65536; // Memory cost (in KB)
  private static final int PARALLELISM = 1; // Degree of parallelism
  private static final int HASH_LENGTH = 64; // Length of the hash in bytes

  public static void main(String[] args) {
    final byte[] salt = generateSalt(SALT_LENGTH);
    final byte[] hash = hashPassword(PASSWORD, salt, ITERATIONS, MEMORY, PARALLELISM, HASH_LENGTH);

    System.out.printf(
        "Generated base64 encoded salt [%s]%n", Base64.getEncoder().encodeToString(salt));
    System.out.printf(
        "Generated base64 encoded hash [%s]%n", Base64.getEncoder().encodeToString(hash));
  }

  /**
   * Generates a random salt of the specified length.
   *
   * <p>The salt is used in hashing functions to ensure that even if two users have the same
   * password, their hashes will be unique. This helps protect against precomputed attacks such as
   * rainbow table attacks.
   */
  private static byte[] generateSalt(int length) {
    final SecureRandom random = new SecureRandom();
    final byte[] salt = new byte[length];
    random.nextBytes(salt);
    return salt;
  }

  private static byte[] hashPassword(
      String password, byte[] salt, int iterations, int memory, int parallelism, int hashLength) {
    final Argon2Parameters.Builder builder =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt) // Salt ensures unique hashes for identical passwords
            .withIterations(iterations) // Iterations increase computational cost for added security
            .withMemoryAsKB(memory) // Memory cost helps resist GPU-based attacks
            .withParallelism(parallelism);

    final Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(builder.build());

    final byte[] hash = new byte[hashLength];
    generator.generateBytes(password.toCharArray(), hash);

    return hash;
  }
}
