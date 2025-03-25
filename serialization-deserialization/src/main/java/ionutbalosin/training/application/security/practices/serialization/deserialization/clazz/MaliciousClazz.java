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
package ionutbalosin.training.application.security.practices.serialization.deserialization.clazz;

import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * This malicious class (typically is created by the attacker) demonstrates a deserialization
 * vulnerability by launching the system calculator upon deserialization. The consequences could be
 * more severe on a real system.
 *
 * <p>This class overrides the readObject method, which plays a key role in Java deserialization,
 * making it a common target for deserialization attacks.
 *
 * <p>Why the readObject method can be dangerous:
 *
 * <ul>
 *   <li><b>Custom Deserialization Logic:</b> The readObject method allows you to provide custom
 *       logic during deserialization. If this method is overridden, it can execute any code,
 *       including unsafe operations like invoking system commands.
 *   <li><b>Implicit Invocation:</b> When deserializing an object via
 *       ObjectInputStream.readObject(), the readObject method in the target class is called
 *       automatically, without explicit invocation. If an attacker can control the serialized data,
 *       they can trigger arbitrary behavior inside this method during deserialization.
 *   <li><b>No Input Validation:</b> If the input data comes from an untrusted source, malicious
 *       serialized data can force the readObject method to run arbitrary code, leading to serious
 *       security issues like Remote Code Execution (RCE).
 * </ul>
 */
public class MaliciousClazz extends TrustedClazz {

  private static final long serialVersionUID = 1L;

  public MaliciousClazz() {
    System.out.printf("A malicious class constructor has been invoked.%n");
  }

  private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();

    final String os = System.getProperty("os.name").toLowerCase();
    final String[] cmd;

    // Determine the appropriate command to launch the calculator based on the OS
    if (os.contains("win")) {
      cmd = new String[] {"cmd.exe", "/c", "calc"};
    } else if (os.contains("mac")) {
      cmd = new String[] {"/bin/sh", "-c", "open -a Calculator"};
    } else if (os.contains("nix") || os.contains("nux")) {
      cmd = new String[] {"/bin/sh", "-c", "gnome-calculator"};
    } else {
      throw new UnsupportedOperationException("Unsupported operating system: " + os);
    }

    System.out.printf("Malicious class launches the Calculator application on [%s]%n", os);
    Runtime.getRuntime().exec(cmd);
  }
}
