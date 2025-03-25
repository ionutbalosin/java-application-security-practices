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
package ionutbalosin.training.application.security.practices.pizza.order.service.validator;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class UploadFileValidator {

  private static final Logger LOG = LoggerFactory.getLogger(UploadFileValidator.class);
  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");

  @Value("${file.upload.max-size}")
  private Integer fileMaxSize;

  @Value("${file.upload.max-filename-length}")
  private Integer fileNameMaxLength;

  @Value("#{'${file.upload.allowed-extensions}'.split(',')}")
  private Set<String> allowedExtensions;

  private final Tika tika;

  public UploadFileValidator() {
    this.tika = new Tika();
  }

  /**
   * This method checks whether the uploaded file meets specific criteria such as size, name length,
   * allowed file extensions, and valid MIME type (JSON or plain text).
   */
  public void validate(MultipartFile uploadFile) {
    final String filename = uploadFile.getOriginalFilename();
    LOG.info("Starting validation for file: {}", filename);

    validateFilenameLength(filename);
    validateFileExtension(filename);
    validateFileSize(uploadFile, filename);
    validateFileMimeType(uploadFile, filename);
    validatePathTraversal(filename);

    LOG.info("File {} passed validation.", filename);
  }

  private void validateFileSize(MultipartFile uploadFile, String filename) {
    if (uploadFile.getSize() > fileMaxSize) {
      throw new SecurityException(
          format(
              "File size %s (bytes) is larger than the allowed size %s (bytes).",
              uploadFile.getSize(), fileMaxSize));
    }

    if (uploadFile.getSize() == 0) {
      throw new SecurityException(format("File %s is empty.", filename));
    }
  }

  private void validateFilenameLength(String filename) {
    if (filename == null || filename.length() > fileNameMaxLength) {
      throw new SecurityException(
          format(
              "File name length %s exceeds the maximum allowed length of %s.",
              filename.length(), fileNameMaxLength));
    }
  }

  private void validateFileExtension(String filename) {
    final String fileExtension = getFileExtension(filename);
    if (!allowedExtensions.stream()
        .anyMatch(allowedExtension -> fileExtension.equalsIgnoreCase(allowedExtension))) {
      throw new SecurityException(format("File extension %s is not allowed.", fileExtension));
    }
  }

  private void validateFileMimeType(MultipartFile uploadFile, String filename) {
    try {
      final String mimeType = tika.detect(uploadFile.getInputStream());
      if (!mimeType.equals("application/json") && !mimeType.equals("text/plain")) {
        throw new SecurityException(format("File MIME type %s is not allowed.", mimeType));
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Validates the specified filename to prevent path traversal attacks.
   *
   * <p>This method checks whether the canonical path of the given filename starts with the base
   * directory's canonical path. If it does not, this may indicate a potential path traversal
   * attempt, and access to files outside the intended directory structure is denied.
   *
   * <p>Path Traversal Attack Example:
   *
   * <p>Suppose CURRENT_DIR is "/uploads". A malicious user could attempt to access sensitive files
   * by providing the following filename: "../../etc/passwd".
   */
  private void validatePathTraversal(String filename) {
    try {
      final File file = new File(CURRENT_DIR, filename);
      final String fileCanonicalPath = file.getCanonicalPath();
      final String currentDirCanonicalPath = new File(CURRENT_DIR).getCanonicalPath();

      if (!fileCanonicalPath.startsWith(currentDirCanonicalPath)) {
        throw new SecurityException(
            format(
                "Path traversal detected for filename: %s. Access to the file is not allowed.",
                filename));
      }

    } catch (IOException e) {
      throw new RuntimeException("Error while validating file path: " + e.getMessage(), e);
    }
  }

  private String getFileExtension(String fileName) {
    return ofNullable(fileName)
        .filter(name -> name.contains("."))
        .map(name -> name.substring(name.lastIndexOf(".") + 1))
        .orElseThrow(
            () ->
                new RuntimeException(
                    format("Could not identify file extension for '%s'", fileName)));
  }
}
