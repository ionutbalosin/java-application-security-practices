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
package ionutbalosin.training.application.security.practices.serialization.deserialization.encryptdecrypt;

import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * This class provides functionality for encrypting a file using AES encryption. It generates a
 * secret key, encrypts a file, and stores the encrypted file and key. The secret key is saved to a
 * separate file for later decryption.
 */
public class FileEncryption {

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  private static final String INITIAL_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/src/main/resources/confidential_file.txt";
  private static final String ENCRYPTED_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/encrypted_file.txt";
  private static final String SECRET_KEY_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/secret.key";

  public static void main(String[] args) throws Exception {
    // Generate a secret key for encryption
    final SecretKey secretKey = generateKey();

    // Encrypt the file using the generated secret key
    encryptFile(INITIAL_FILENAME, ENCRYPTED_FILENAME, secretKey);
    System.out.printf("File successfully encrypted to [%s]%n", ENCRYPTED_FILENAME);

    // Save the secret key to a file for later decryption
    saveKey(secretKey);
    System.out.printf("Encryption key successfully saved to [%s]%n", SECRET_KEY_FILENAME);
  }

  private static void saveKey(SecretKey secretKey) throws Exception {
    try (final ObjectOutputStream keyOut =
        new ObjectOutputStream(new FileOutputStream(SECRET_KEY_FILENAME))) {
      keyOut.writeObject(secretKey);
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

  private static void encryptFile(String filePath, String encryptedFilePath, SecretKey secretKey)
      throws Exception {
    final Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

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
