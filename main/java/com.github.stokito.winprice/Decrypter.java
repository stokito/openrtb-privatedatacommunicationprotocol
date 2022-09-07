package com.github.stokito.winprice;
// Copyright 2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Decrypter is sample code showing the steps to decrypt and verify 64-bit
// values. It uses the Base 64 decoder from the Apache commons project
// (http://commons.apache.org).

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;

/**
 * An Exception thrown by Decrypter if the ciphertext cannot successfully be
 * decrypted.
 */
class DecrypterException extends Exception {
  public DecrypterException(String message) {
    super(message);
  }
}

/**
 * Java language sample code for 64 bit value decryption
 */
public class Decrypter {
  /** The length of the initialization vector */
  public static final int INITIALIZATION_VECTOR_SIZE = 16;
  /** The length of the ciphertext */
  private static final int CIPHERTEXT_SIZE = 8;
  /** The length of the signature */
  private static final int SIGNATURE_SIZE = 4;
  /** The fixed block size for the block cipher */
  private static final int BLOCK_SIZE = 20;

  /**
   * Performs the decryption algorithm.
   *
   * This method decrypts the ciphertext using the encryption key and verifies
   * the integrity bits with the integrity key. The encrypted format is:
   *   {initialization_vector (16 bytes)}{ciphertext}{integrity (4 bytes)}
   * https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-hyperlocal,
   * https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price
   * and https://support.google.com/adxbuyer/answer/3221407?hl=en have more
   * details about the encrypted format of hyperlocal, winning price,
   * IDFA, hashed IDFA and Android Advertiser ID.
   */
  public static byte[] decrypt(byte[] ciphertext,
                               SecretKey encryptionKey,
                               SecretKey integrityKey)
      throws DecrypterException {
    try {
      // Step 1. find the length of initialization vector and clear text.
      final int plaintext_length =
          ciphertext.length - INITIALIZATION_VECTOR_SIZE - SIGNATURE_SIZE;
      if (plaintext_length < 0) {
        throw new RuntimeException("The plain text length can't be negative.");
      }

      byte[] iv = Arrays.copyOf(ciphertext, INITIALIZATION_VECTOR_SIZE);

      // Step 2. recover clear text
      final Mac hmacer = Mac.getInstance("HmacSHA1");
      final int ciphertext_end = INITIALIZATION_VECTOR_SIZE + plaintext_length;
      final byte[] plaintext = new byte[plaintext_length];
      boolean add_iv_counter_byte = true;
      for (int ciphertext_begin = INITIALIZATION_VECTOR_SIZE, plaintext_begin = 0;
           ciphertext_begin < ciphertext_end;) {
        hmacer.reset();
        hmacer.init(encryptionKey);
        final byte[] pad = hmacer.doFinal(iv);

        int i = 0;
        while (i < BLOCK_SIZE && ciphertext_begin != ciphertext_end) {
          plaintext[plaintext_begin++] =
              (byte)(ciphertext[ciphertext_begin++] ^ pad[i++]);
        }

        if (!add_iv_counter_byte) {
          final int index = iv.length - 1;
          add_iv_counter_byte = ++iv[index] == 0;
        }

        if (add_iv_counter_byte) {
          add_iv_counter_byte = false;
          iv = Arrays.copyOf(iv, iv.length + 1);
        }
      }

      // Step 3. Compute integrity hash. The input to the HMAC is clear_text
      // followed by initialization vector, which is stored in the 1st section
      // or ciphertext.
      hmacer.reset();
      hmacer.init(integrityKey);
      hmacer.update(plaintext);
      hmacer.update(Arrays.copyOf(ciphertext, INITIALIZATION_VECTOR_SIZE));
      final byte[] computedSignature = Arrays.copyOf(hmacer.doFinal(), SIGNATURE_SIZE);
      final byte[] signature = Arrays.copyOfRange(
          ciphertext, ciphertext_end, ciphertext_end + SIGNATURE_SIZE);
      if (!Arrays.equals(signature, computedSignature)) {
        throw new DecrypterException("Signature mismatch.");
      }
      return plaintext;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("HmacSHA1 not supported.", e);
    } catch (InvalidKeyException e) {
      throw new RuntimeException("Key is invalid for this purpose.", e);
    }
  }

  /**
   * Parses the timestamp out of the initialization vector. Note: this method
   * loses precision. java.util.Date only holds the date to millisecond
   * precision while the initialization vector contains a timestamp with
   * microsecond precision.
   */
  public static Instant getTimeFromInitializationVector(
      byte[] initializationVector) {
    ByteBuffer buffer = ByteBuffer.wrap(initializationVector);
    long seconds = buffer.getInt();
    long micros = buffer.getInt();
    return Instant.ofEpochMilli((seconds * 1000) + (micros / 1000));
  }
}
