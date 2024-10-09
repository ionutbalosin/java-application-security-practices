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
package ionutbalosin.training.application.security.practices.serialization.deserialization.clazz;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

/**
 * This class demonstrates Java deserialization vulnerabilities by showing how a malicious class can
 * be serialized by an attacker and then deserialized on a target machine to trigger unwanted
 * behavior. It also includes an example of secure deserialization using a validation list to
 * prevent deserialization attacks.
 *
 * <p>References:
 *
 * <ul>
 *   <li>Code examples inspired from Brian Vermeer (Twitter: <a
 *       href="https://twitter.com/BrianVerm">@BrianVerm</a>)
 *   <li><a href="https://foojay.io/today/explaining-java-deserialization-vulnerabilities-part-1">
 *       Explaining Java Deserialization Vulnerabilities (Part 1)</a>
 *   <li><a href="https://foojay.io/today/explaining-java-deserialization-vulnerabilities-part-2">
 *       Explaining Java Deserialization Vulnerabilities (Part 2)</a>
 * </ul>
 */
public class MaliciousClazzDeserializer {

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  private static final String CLASS_FILENAME =
      CURRENT_DIR + "/serialization/target/malicious_class.ser";

  public static void main(String[] args) {
    // Serialize the malicious class (typically this is done by the attacker)
    serialize(CLASS_FILENAME);

    // Deserialize the malicious class (this will trigger the calculator application to open).
    // Typically, this is done on the vulnerable client's side.
    deserialize(CLASS_FILENAME);

    // Deserialize using a validation list to prevent deserialization of the malicious class.
    // Typically, this is done on the secure client's side to avoid deserialization attacks.
    deserializeWithValidation(CLASS_FILENAME);
  }

  private static void serialize(String filename) {
    System.out.printf("*** Serialization ***%n");
    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
      MaliciousClazz maliciousClazz = new MaliciousClazz();
      oos.writeObject(maliciousClazz);
      System.out.printf("Successfully serialized to [%s]%n", filename);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private static void deserialize(String filename) {
    System.out.printf("*** Deserialization ***%n");
    try (final ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
      // Note: While casting is not essential in this example, the key point is the invocation of
      // the readObject() method, which triggers the custom deserialization logic and can lead to
      // vulnerabilities.
      final TrustedClazz trustedClazz = (TrustedClazz) ois.readObject();
      System.out.printf("Successfully deserialized from [%s]%n", filename);
    } catch (IOException | ClassNotFoundException e) {
      e.printStackTrace();
    }
  }

  private static void deserializeWithValidation(String filename) {
    System.out.printf("*** Deserialization with validation ***%n");
    try (final FileInputStream fis = new FileInputStream(filename);
        final ValidatingObjectInputStream vois = new ValidatingObjectInputStream(fis)) {
      // Only allow specific trusted classes (e.g., TrustedClass) to be deserialized
      vois.accept(TrustedClazz.class);
      // Deserialize the object (only allowed classes can be deserialized)
      final TrustedClazz trustedClazz = (TrustedClazz) vois.readObject();
      System.out.printf("Successfully deserialized from [%s]%n", filename);
    } catch (IOException | ClassNotFoundException e) {
      e.printStackTrace();
    }
  }
}
