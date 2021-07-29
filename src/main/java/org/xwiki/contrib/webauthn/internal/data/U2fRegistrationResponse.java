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

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import lombok.NonNull;
import lombok.Value;

/**
 * The U2f registration response generated after a successful registration request.
 *
 * @version $Id$
 */
@Value
public class U2fRegistrationResponse
{
    ByteArray requestId;

    U2fCredential credential;

    Optional<ByteArray> sessionToken;

    /**
     * Instantiates a new U2f registration response.
     *
     * @param requestId the id for the newly generated public-key credential
     * @param credential the public-key credential
     * @param sessionToken the session token
     */
    @JsonCreator
    public U2fRegistrationResponse(
        @NonNull @JsonProperty("requestId") ByteArray requestId,
        @NonNull @JsonProperty("credential") U2fCredential credential,
        @NonNull @JsonProperty("sessionToken") Optional<ByteArray> sessionToken)
    {
        this.requestId = requestId;
        this.credential = credential;
        this.sessionToken = sessionToken;
    }
}
