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
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * This class handles the decryption of an encrypted file using AES-256 encryption with GCM mode. It
 * loads a saved secret key and initialization vector (IV), decrypts the file, and stores the
 * decrypted content.
 */
public class FileDecryption {

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  private static final String ENCRYPTED_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/encrypted_file.txt";
  private static final String DECRYPTED_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/decrypted_file.txt";
  private static final String SECRET_KEY_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/secret.key";
  private static final String IV_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/target/iv.key";

  public static void main(String[] args) throws Exception {
    // Load the secret key and IV from the files for decryption
    final SecretKey secretKey = loadKey();
    final byte[] iv = loadIv();

    // Decrypt the encrypted file using the loaded secret key and IV
    decryptFile(ENCRYPTED_FILENAME, DECRYPTED_FILENAME, secretKey, iv);
    System.out.printf("File successfully decrypted to [%s]%n", DECRYPTED_FILENAME);
  }

  private static SecretKey loadKey() throws Exception {
    try (final ObjectInputStream keyIn =
        new ObjectInputStream(new FileInputStream(SECRET_KEY_FILENAME))) {
      return (SecretKey) keyIn.readObject();
    }
  }

  private static byte[] loadIv() throws Exception {
    try (FileInputStream ivIn = new FileInputStream(IV_FILENAME)) {
      return ivIn.readAllBytes();
    }
  }

  private static void decryptFile(
      String encryptedFilePath, String decryptedFilePath, SecretKey secretKey, byte[] iv)
      throws Exception {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

    try (final FileInputStream fileInputStream = new FileInputStream(encryptedFilePath);
        final FileOutputStream fileOutputStream = new FileOutputStream(decryptedFilePath);
        final CipherInputStream cipherInputStream =
            new CipherInputStream(fileInputStream, cipher)) {

      final byte[] buffer = new byte[1024];
      int bytesRead;
      while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
        fileOutputStream.write(buffer, 0, bytesRead);
      }
    }
  }
}
