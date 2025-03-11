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
package ionutbalosin.training.application.security.practices.serialization.deserialization.encryptdecrypt.symetric;

import java.io.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * This class provides functionality for encrypting a file using AES encryption with GCM mode. It
 * generates a secret key and an initialization vector (IV), encrypts a file, and stores the
 * encrypted file, secret key, and IV. The secret key and IV are saved to separate files for later
 * decryption.
 */
public class FileEncryption {

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  private static final String INITIAL_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/src/main/resources/confidential_file.txt";
  private static final String ENCRYPTED_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/encrypted_file_aes.txt";
  private static final String SECRET_KEY_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/secret_aes.key";
  private static final String IV_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/iv_aes.key";

  public static void main(String[] args) throws Exception {
    // Generate a secret key and IV for encryption
    final SecretKey secretKey = generateKey();
    final byte[] iv = generateIv();

    // Encrypt the file using the generated secret key
    encryptFile(INITIAL_FILENAME, ENCRYPTED_FILENAME, secretKey, iv);
    System.out.printf("File successfully encrypted to [%s]%n", ENCRYPTED_FILENAME);

    // Save the secret key and IV to files for later decryption
    saveKey(secretKey);
    saveIv(iv);
    System.out.printf("Encryption key successfully saved to [%s]%n", SECRET_KEY_FILENAME);
  }

  private static void saveKey(SecretKey secretKey) throws Exception {
    try (final ObjectOutputStream keyOut =
        new ObjectOutputStream(new FileOutputStream(SECRET_KEY_FILENAME))) {
      keyOut.writeObject(secretKey);
    }
  }

  private static void saveIv(byte[] iv) throws Exception {
    try (FileOutputStream ivOut = new FileOutputStream(IV_FILENAME)) {
      ivOut.write(iv);
    }
  }

  private static SecretKey generateKey() throws Exception {
    // Note: AES-256 offers a very high level of security. As of today, there are no practical
    // attacks that can break AES-256 encryption within a reasonable time frame, even using
    // supercomputers.
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    return keyGenerator.generateKey();
  }

  private static byte[] generateIv() throws Exception {
    // Note: IV (Initialization Vector) is used in encryption algorithms, particularly in modes that
    // provide authenticated encryption like AES/GCM, to ensure uniqueness and security of the
    // encryption process. The IV adds randomness to the encryption process, ensuring that the same
    // plaintext encrypted multiple times with the same key will produce different ciphertexts.
    final byte[] iv = new byte[12];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(iv);
    return iv;
  }

  private static void encryptFile(
      String filePath, String encryptedFilePath, SecretKey secretKey, byte[] iv) throws Exception {
    // Using AES/GCM/NoPadding is in line with OWASP recommendations for the authenticated
    // encryption.
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

    try (final FileInputStream fileInputStream = new FileInputStream(filePath);
        final FileOutputStream fileOutputStream = new FileOutputStream(encryptedFilePath);
        final CipherOutputStream cipherOutputStream =
            new CipherOutputStream(fileOutputStream, cipher)) {

      final byte[] buffer = new byte[1024];
      int bytesRead;

      while ((bytesRead = fileInputStream.read(buffer)) != -1) {
        cipherOutputStream.write(buffer, 0, bytesRead);
      }
    }
  }
}
