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
package ionutbalosin.training.application.security.practices.serialization.deserialization.xml;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

/**
 * This class demonstrates a potential security vulnerability caused by XML External Entity (XXE)
 * injection. The application reads and parses an XML file that may contain an external entity
 * reference. These external entities can reference sensitive information, such as application
 * properties (e.g., database passwords) or system files (e.g., /etc/passwd on Unix-like systems).
 *
 * <p>This vulnerability occurs when an application processes untrusted XML files without properly
 * disabling external entity resolution. Attackers can exploit this to access sensitive data or
 * perform Denial of Service (DoS) attacks by providing malicious XML inputs.
 */
public class XmlXxeDeserializer {

  private static final String CURRENT_DIR = System.getProperty("user.dir", ".");
  private static final String CLASS_FILENAME =
      CURRENT_DIR + "/serialization-deserialization/src/main/resources/xml_external_entity.xml";

  public static void main(String[] args)
      throws IOException, ParserConfigurationException, SAXException {

    System.out.printf("*** Deserialization ***%n");
    final XMLReader defaultReader = createXmlReader();
    deserialize(CLASS_FILENAME, defaultReader);
    System.out.printf("Successfully deserialized from [%s]%n", CLASS_FILENAME);

    System.out.printf("*** Deserialization with XXE protection ***%n");
    final XMLReader readerWithXseProtection = createXmlReaderWithXseProtection();
    deserialize(CLASS_FILENAME, readerWithXseProtection);
    System.out.printf("Successfully deserialized from [%s]%n", CLASS_FILENAME);
  }

  private static XMLReader createXmlReader() throws ParserConfigurationException, SAXException {
    final SAXParserFactory factory = SAXParserFactory.newInstance();
    return factory.newSAXParser().getXMLReader();
  }

  private static XMLReader createXmlReaderWithXseProtection()
      throws ParserConfigurationException, SAXException {
    final SAXParserFactory factory = SAXParserFactory.newInstance();
    // Disable DTDs and external entities for XXE protection
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

    return factory.newSAXParser().getXMLReader();
  }

  private static void deserialize(String filename, XMLReader reader)
      throws IOException, SAXException {
    final ByteArrayOutputStream xmlByteArray = new ByteArrayOutputStream();

    // Set a content handler to write the characters to the byte array output stream
    reader.setContentHandler(
        new DefaultHandler() {
          @Override
          public void characters(char[] ch, int start, int length) {
            try {
              xmlByteArray.write(new String(ch, start, length).getBytes());
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        });

    // Parse the XML file
    try (InputStream is = new FileInputStream(filename)) {
      reader.parse(new InputSource(is));
    }

    System.out.println(new String(xmlByteArray.toByteArray()));
  }
}
