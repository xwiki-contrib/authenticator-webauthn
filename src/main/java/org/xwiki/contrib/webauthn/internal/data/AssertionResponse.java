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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

/**
 * Properties associated with a WebAuthn assertion response.
 *
 * @version $Id$
 */
@Value
@JsonIgnoreProperties({"sessionToken"})
public class AssertionResponse
{
    ByteArray requestId;

    PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;

    /**
     * Instantiates a new Assertion response.
     *
     * @param requestId the request id
     * @param credential the public-key credential
     */
    public AssertionResponse(@JsonProperty("requestId") ByteArray requestId,
        @JsonProperty("credential") PublicKeyCredential<AuthenticatorAssertionResponse,
            ClientAssertionExtensionOutputs> credential)
    {
        this.requestId = requestId;
        this.credential = credential;
    }
}
