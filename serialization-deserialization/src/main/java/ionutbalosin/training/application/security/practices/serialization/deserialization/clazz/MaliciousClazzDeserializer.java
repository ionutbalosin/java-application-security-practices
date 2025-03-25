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
import java.io.ObjectInputFilter;
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
      CURRENT_DIR + "/serialization-deserialization/target/malicious_class.ser";

  public static void main(String[] args) {
    // Serialize the malicious class.
    // Typically, this is performed by an attacker.
    serialize(CLASS_FILENAME);

    // Perform default Java deserialization, which triggers the calculator application
    // defined in the malicious class.
    // Typically, this is done on the vulnerable client's side.
    defaultDeserialize(CLASS_FILENAME);

    // Deserialize using the Java input filter to restrict deserialization
    // and prevent the malicious class from being processed.
    // Typically, this is done on the vulnerable client's side.
    deserializeWithJavaObjectInputFilter(CLASS_FILENAME);

    // Deserialize using Apache Commons validation to prevent deserialization
    // of the malicious class by enforcing validation rules.
    // Typically, this is done on the vulnerable client's side.
    deserializeWithApacheCommonsValidatingObjectInputStream(CLASS_FILENAME);
  }

  private static void serialize(String filename) {
    System.out.printf("%n*** Serialization ***%n");
    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
      final MaliciousClazz maliciousClazz = new MaliciousClazz();
      oos.writeObject(maliciousClazz);
      System.out.printf("Successfully serialized to [%s]%n", filename);
    } catch (IOException e) {
      System.out.printf("Exception encountered: %s%n", e.getMessage());
    }
  }

  private static void defaultDeserialize(String filename) {
    System.out.printf("%n*** Default deserialization ***%n");
    try (final ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
      // Deserialize the object, expecting it to be of type TrustedClazz
      final TrustedClazz trustedClazz = (TrustedClazz) ois.readObject();
      System.out.printf("Successfully deserialized from [%s]%n", filename);
    } catch (IOException | ClassNotFoundException e) {
      System.out.printf("Exception encountered: %s%n", e.getMessage());
    }
  }

  private static void deserializeWithJavaObjectInputFilter(String filename) {
    System.out.printf("%n*** Deserialization with Java ObjectInputFilter ***%n");
    try (final ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
      // Create a filter that allows deserialization of TrustedClazz class and rejects all others.
      // The filter string format: <class name>;!* (allow TrustedClazz, reject all other classes).
      final ObjectInputFilter filesOnlyFilter =
          ObjectInputFilter.Config.createFilter(TrustedClazz.class.getName() + ";!*");
      ois.setObjectInputFilter(filesOnlyFilter);
      // Deserialize the object, expecting it to be of type TrustedClazz
      final TrustedClazz trustedClazz = (TrustedClazz) ois.readObject();
      System.out.printf("Successfully deserialized from [%s]%n", filename);
    } catch (IOException | ClassNotFoundException e) {
      System.out.printf("Exception encountered: %s%n", e.getMessage());
    }
  }

  private static void deserializeWithApacheCommonsValidatingObjectInputStream(String filename) {
    System.out.printf(
        "%n*** Deserialization with Apache Commons ValidatingObjectInputStream ***%n");
    try (final FileInputStream fis = new FileInputStream(filename);
        final ValidatingObjectInputStream vois = new ValidatingObjectInputStream(fis)) {
      // Only allow specific trusted classes (e.g., TrustedClazz) to be deserialized
      vois.accept(TrustedClazz.class);
      // Deserialize the object (only allowed classes can be deserialized)
      final TrustedClazz trustedClazz = (TrustedClazz) vois.readObject();
      System.out.printf("Successfully deserialized from [%s]%n", filename);
    } catch (IOException | ClassNotFoundException e) {
      System.out.printf("Exception encountered: %s%n", e.getMessage());
    }
  }
}
