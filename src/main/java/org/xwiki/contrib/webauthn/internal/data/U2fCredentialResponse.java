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

/**
 * The webauthn credential response generated after a successful registration request.
 *
 * @version $Id$
 */
@Value
public class U2fCredentialResponse
{
    ByteArray keyHandle;

    ByteArray publicKey;

    ByteArray attestationCertAndSignature;

    ByteArray clientDataJSON;

    /**
     * Instantiates a new U2f credential response.
     *
     * @param keyHandle key handle for the public-key
     * @param publicKey the public-key credential
     * @param attestationCertAndSignature the attestation certificate and signature
     * @param clientDataJSON the data passed from client to authenticator in order to associate a new credential
     */
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