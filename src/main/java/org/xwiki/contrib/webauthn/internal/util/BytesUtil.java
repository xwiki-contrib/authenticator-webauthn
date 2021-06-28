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

/**
 * Helper class for interconversion b/w long and bytes
 *
 * @version $Id$
 */
public class BytesUtil
{
    public static byte[] longToBytes(long longValue)
    {
        long l = longValue;

        byte[] result = new byte[8];

        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (l & 0xFF);
            l >>= 8;
        }

        return result;
    }

    public static long bytesToLong(byte[] b)
    {
        long result = 0;

        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result |= b[i] & 0xFF;
        }

        return result;
    }

}
