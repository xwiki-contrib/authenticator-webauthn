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
package org.xwiki.contrib.webauthn.internal.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import lombok.NonNull;
import lombok.Value;

@Value
public class U2fCredentialResponse
{

    private final ByteArray keyHandle;

    private final ByteArray publicKey;

    private final ByteArray attestationCertAndSignature;

    private final ByteArray clientDataJSON;

    @JsonCreator
    public U2fCredentialResponse(
        @NonNull @JsonProperty("keyHandle") ByteArray keyHandle,
        @NonNull @JsonProperty("publicKey") ByteArray publicKey,
        @NonNull @JsonProperty("attestationCertAndSignature") ByteArray attestationCertAndSignature,
        @NonNull @JsonProperty("clientDataJSON") ByteArray clientDataJSON)
    {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        this.attestationCertAndSignature = attestationCertAndSignature;
        this.clientDataJSON = clientDataJSON;
    }
}