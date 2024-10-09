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
package ionutbalosin.training.application.security.practices.serialization.deserialization.zip;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * This Java class prevents zip bomb attacks by enforcing strict limits on the decompression
 * process. It restricts the maximum uncompressed size, the number of zip entries, and the nesting
 * depth for recursively zipped files. These safeguards mitigate potential attacks that exploit
 * excessive resource usage, such as zip bombs, which can cause Denial of Service (DoS) by
 * overwhelming system memory or storage.
 *
 * <p>References:
 *
 * <ul>
 *   <li><a href="https://www.bamsoftware.com/hacks/zipbomb">A better zip bomb</a>
 *   <li><a href="https://unforgettable.dk">42.zip bomb</a>
 * </ul>
 */
public class ZipBombDeserializer {

  private static final long ONE_MB = 1024 * 1024;
  private static final long MAX_UNCOMPRESSED_SIZE = 1024 * ONE_MB; // 1 GB max uncompressed size
  private static final int MAX_ENTRIES = 10_000; // Max 10,000 entries
  private static final int MAX_NESTING_DEPTH = 20; // Max zip nesting depth

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  // Note: The size on disk of zbsm.zip is 42 kB, but it expands to 5.5 GB when extracted.
  private static final String CLASS_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/src/main/resources/zbsm.zip";

  public static void main(String[] args) throws IOException {
    final File zipFile = new File(CLASS_FILENAME);
    extractZipFile(zipFile, 0);
  }

  public static void extractZipFile(File file, int depth) throws IOException {
    if (depth > MAX_NESTING_DEPTH) {
      throw new IllegalStateException(
          String.format(
              "Max zip nesting depth [%d] exceeded. Possible zip bomb!", MAX_NESTING_DEPTH));
    }

    try (ZipFile zipFile = new ZipFile(file)) {
      final Enumeration<? extends ZipEntry> entries = zipFile.entries();
      long totalUncompressedSize = 0;
      int entryCount = 0;

      while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();

        if (entryCount++ > MAX_ENTRIES) {
          throw new IllegalStateException(
              String.format("Max zip entries [%d] exceeded. Possible zip bomb!", MAX_ENTRIES));
        }

        if (!entry.isDirectory()) {
          long entrySize = entry.getSize();
          if (entrySize < 0) {
            entrySize = 0;
          }
          totalUncompressedSize += entrySize;

          if (totalUncompressedSize > MAX_UNCOMPRESSED_SIZE) {
            throw new IllegalStateException(
                String.format(
                    "Max uncompressed zip size [%d] MB exceeded. Possible zip bomb!",
                    MAX_UNCOMPRESSED_SIZE / ONE_MB));
          }

          if (entry.getName().endsWith(".zip")) {
            System.out.printf("Detected nested entry [%s]%n", entry.getName());
            final File nestedZip = new File(entry.getName());
            try (InputStream is = zipFile.getInputStream(entry)) {
              Files.copy(is, nestedZip.toPath());
            }
            try {
              extractZipFile(nestedZip, depth + 1);
            } finally {
              nestedZip.delete(); // Ensure cleanup in case of failure
            }
          } else {
            String sizeStr =
                entrySize >= ONE_MB
                    ? String.format("%d MB", entrySize / ONE_MB)
                    : String.format("%d KB", entrySize / 1024);
            System.out.printf("Extracting zip entry [%s] of size [%s]%n", entry.getName(), sizeStr);
            try (InputStream is = zipFile.getInputStream(entry)) {
              final byte[] buffer = new byte[8192]; // 8 KB buffer
              while (is.read(buffer) != -1) {
                // TODO: simulate reading
              }
            }
          }
        }
      }
    }
  }
}
