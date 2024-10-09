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
package ionutbalosin.training.application.security.practices.serialization.deserialization.yaml;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

/**
 * This class reads and parses a YAML file containing a deeply recursive structure, referred to as a
 * "YAML bomb", using the SnakeYAML library. Parsing such a YAML structure may consume excessive CPU
 * or memory, potentially causing the application to crash or become unavailable, making it a
 * potential vector for denial-of-service (DoS) attacks.
 *
 * <p>This vulnerability can occur when the application receives an external YAML file as input and
 * attempts to load it.
 *
 * <p>Note: Versions of SnakeYAML prior to 1.26 are susceptible to this vulnerability. Starting from
 * version 1.26, this type of attack is prevented, as the library imposes a limit on the depth of
 * nested structures.
 *
 * <p>References:
 *
 * <ul>
 *   <li><a href="https://github.com/dubniczky/Yaml-Bomb">Yaml Bomb</a>
 *   <li><a href="https://snyk.io/blog/java-yaml-parser-with-snakeyaml/">Preventing YAML parsing
 *       vulnerabilities with SnakeYAML in Java</a>
 * </ul>
 */
public class YamlBombDeserializer {

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  private static final String CLASS_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/src/main/resources/yaml_bomb.yaml";

  public static void main(String[] args) throws IOException {
    System.out.printf("*** Deserialization ***%n");
    try (InputStream inputStream = new BufferedInputStream(new FileInputStream(CLASS_FILENAME))) {
      final Yaml yaml = new Yaml();
      final Map<String, Object> data = yaml.load(inputStream);
      final List<User> users = (List<User>) data.get("user");
    }
  }
}
