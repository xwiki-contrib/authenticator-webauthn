/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.webauthn.internal.util;

import java.util.Arrays;

/**
 * Helper class for encoding and decoding
 *
 * @version $Id$
 */
public class Base58
{
    public static final char[] CHAR_STRING = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    private static final char ENCODED_ZERO = CHAR_STRING[0];

    private static final int[] INDEXES = new int[128];

    static
    {
        Arrays.fill(INDEXES, -1);

        for (int i = 0; i < CHAR_STRING.length; i++) {
            INDEXES[CHAR_STRING[i]] = i;
        }
    }

    /**
     * Encodes the given bytes as a base58 string (no checksum is appended).
     *
     * @param inputValue the bytes to encode
     * @return the base58-encoded string
     */
    public static String encode(byte[] inputValue)
    {
        byte[] input = inputValue;

        if (input.length == 0) {
            return "";
        }

        // Count leading zeros.
        int zeros = 0;

        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }

        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters), since we modify it in-place
        input = Arrays.copyOf(input, input.length);

        // upper bound
        char[] encoded = new char[input.length * 2];

        int outputStart = encoded.length;

        for (int inputStart = zeros; inputStart < input.length;) {
            encoded[--outputStart] = CHAR_STRING[divMod(input, inputStart, 256, 58)];

            if (input[inputStart] == 0) {
                // optimization - skip leading zeros
                ++inputStart;
            }
        }

        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart;
        }

        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO;
        }

        // Return encoded string (including encoded leading zeros).
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    /**
     * Decodes the given base58 string into the original data bytes.
     *
     * @param input the base58-encoded string to decode
     * @return the decoded data bytes
     * @throws IllegalArgumentException if the given string is not a valid base58 string
     */
    public static byte[] decode(String input)
    {
        if (input.length() == 0) {
            return new byte[0];
        }

        // Convert the base58-encoded ASCII characters to a base58 byte sequence (base58 digits).
        byte[] input58 = new byte[input.length()];

        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);

            int digit = c < 128 ? INDEXES[c] : -1;

            if (digit < 0) {
                throw new IllegalArgumentException("Invalid character: " + c + " at pos " + i);
            }

            input58[i] = (byte) digit;
        }

        // Count leading zeros.
        int zeros = 0;

        while (zeros < input58.length && input58[zeros] == 0) {
            ++zeros;
        }

        // Convert base-58 digits to base-256 digits.
        byte[] decoded = new byte[input.length()];

        int outputStart = decoded.length;

        for (int inputStart = zeros; inputStart < input58.length;) {
            decoded[--outputStart] = divMod(input58, inputStart, 58, 256);

            if (input58[inputStart] == 0) {
                // optimization - skip leading zeros
                ++inputStart;
            }
        }

        // Ignore extra leading zeroes that were added during the calculation.
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            ++outputStart;
        }

        // Return decoded data (including original number of leading zeros).
        return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
    }

    /**
     * Divides a number, represented as an array of bytes each containing a single digit in
     * the specified base, by the given divisor. The given number is modified in-place to
     * contain the quotient, and the return value is the remainder.
     *
     * @param number the number to divide
     * @param firstDigit the index within the array of the first non-zero digit (this is
     * used for optimization by skipping the leading zeros)
     * @param base the base in which the number's digits are represented (up to 256)
     * @param divisor the number to divide by (up to 256)
     * @return the remainder of the division operation
     */
    private static byte divMod(byte[] number, int firstDigit, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;

        for (int i = firstDigit; i < number.length; i++) {
            int digit = number[i] & 0xFF;

            int temp = remainder * base + digit;

            number[i] = (byte) (temp / divisor);

            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
}