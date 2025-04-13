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
package ionutbalosin.training.application.security.practices.encryption.decryption.asymetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;

/**
 * This class, demonstrates encrypting and decrypting a short message using RSA encryption. It
 * generates an RSA key pair, encrypts a message with the public key, and decrypts it with the
 * private key. The encrypted message is encoded in Base64 for readability.
 */
public class MessageEncryptDecrypt {

  private static final byte[] SECRET_MESSAGE =
      "Top secret: The universe’s best coffee recipe is hidden here... but first, decrypt me!"
          .getBytes();

  public static void main(String[] args) throws Exception {
    // Generate a key pair for encryption
    final KeyPair keyPair = generateKeyPair();
    final PrivateKey privateKey = keyPair.getPrivate();
    final PublicKey publicKey = keyPair.getPublic();

    // Encrypt the message using the generated public key
    final byte[] encryptedMessage = encryptMessage(SECRET_MESSAGE, publicKey);
    System.out.printf(
        "Generated base64 encoded encrypted message [%s]%n",
        Base64.getEncoder().encodeToString(encryptedMessage));

    // Decrypt the message using the generated private key
    final byte[] decryptedMessage = decryptMessage(encryptedMessage, privateKey);
    System.out.printf("Decrypted message: [%s]%n", new String(decryptedMessage));
  }

  private static KeyPair generateKeyPair() throws Exception {
    // Generate RSA key pair with 2048-bit key size
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private static byte[] encryptMessage(byte[] message, PublicKey publicKey) throws Exception {
    // Note: RSA can only encrypt data smaller than the key size minus padding overhead.
    // For a 2048-bit key and PKCS1 padding, this is generally less than 254 bytes.
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    return cipher.doFinal(message);
  }

  private static byte[] decryptMessage(byte[] encryptedMessage, PrivateKey privateKey)
      throws Exception {
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);

    return cipher.doFinal(encryptedMessage);
  }
}
