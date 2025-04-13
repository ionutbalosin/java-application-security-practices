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
import java.security.Signature;
import java.util.Base64;

/**
 * This class demonstrates the use of digital signatures to ensure non-repudiation, message
 * integrity, and authenticity. By generating an RSA key pair, signing a secret message with the
 * private key, and verifying the signature with the corresponding public key, this class highlights
 * how cryptographic techniques can prevent denial of the message's origin and guarantee that the
 * message has not been altered.
 */
public class DigitalSignatureVerifier {

  private static final byte[] SECRET_MESSAGE =
      "Top secret: The universe’s best coffee recipe is hidden here... but first, decrypt me!"
          .getBytes();

  public static void main(String[] args) throws Exception {
    // Generate a key pair for encryption
    final KeyPair keyPair = generateKeyPair();
    final PrivateKey privateKey = keyPair.getPrivate();
    final PublicKey publicKey = keyPair.getPublic();

    // Sign the data using the private key
    final byte[] digitalSignature = signData(SECRET_MESSAGE, privateKey);
    System.out.printf(
        "Generated digital signature [%s]%n", Base64.getEncoder().encodeToString(digitalSignature));

    // Verify the digital signature using the public key
    final boolean isVerified = verifySignature(SECRET_MESSAGE, digitalSignature, publicKey);
    System.out.printf("Is signature verified: [%s]%n", isVerified);
  }

  // Method to generate an RSA key pair
  private static KeyPair generateKeyPair() throws Exception {
    // Generate RSA key pair with 2048-bit key size
    final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);

    return keyGen.generateKeyPair();
  }

  // Method to sign data using a private key
  private static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
    final Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data);

    return signature.sign();
  }

  // Method to verify a digital signature using a public key
  private static boolean verifySignature(byte[] data, byte[] digitalSignature, PublicKey publicKey)
      throws Exception {
    final Signature signatureVerify = Signature.getInstance("SHA256withRSA");
    signatureVerify.initVerify(publicKey);
    signatureVerify.update(data);

    return signatureVerify.verify(digitalSignature);
  }
}
