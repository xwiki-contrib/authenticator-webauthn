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
package org.xwiki.contrib.webauthn.internal.exception;

import com.yubico.webauthn.data.ByteArray;

import lombok.EqualsAndHashCode;
import lombok.Value;

/**
 * WebAuthn error regarding signature count(number of assertions) for every user
 *
 * @version $Id$
 */
@Value
@EqualsAndHashCode(callSuper = true)
public class WebAuthnInvalidSignatureCountException extends WebAuthnAssertionFailedException
{
    private final ByteArray credentialId;
    private final long expectedMinimum;
    private final long recieved;

    /**
     * Constructs a new exception if the signature count does not increase after the current assertion
     *
     * @param credentialId the credential ID of the xwiki user
     * @param expectedMinimum the number of signatures before the current assertion
     * @param recieved the number of signatures after the current assertion
     */
    public WebAuthnInvalidSignatureCountException(ByteArray credentialId, long expectedMinimum, long recieved)
    {
        super(String.format("Signature count must increase. Expected minimum: %s, Recieved value: %s",
            expectedMinimum, recieved));

        this.credentialId = credentialId;
        this.expectedMinimum = expectedMinimum;
        this.recieved = recieved;
    }

}
