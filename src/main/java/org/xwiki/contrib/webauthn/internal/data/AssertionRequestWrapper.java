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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import lombok.NonNull;
import lombok.Value;

/**
 * Properties associated with a WebAuthn assertion request for a username.
 *
 * @version $Id$
 */
@Value
public class AssertionRequestWrapper
{
    @NonNull ByteArray requestId;

    @NonNull PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @NonNull Optional<String> username;

    @NonNull @JsonIgnore transient AssertionRequest request;

    /**
     * Instantiates a new Assertion request wrapper.
     *
     * @param requestId the request id
     * @param request the request
     */
    public AssertionRequestWrapper(@NonNull ByteArray requestId, @NonNull AssertionRequest request)
    {
        this.requestId = requestId;
        this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
        this.username = request.getUsername();
        this.request = request;
    }
}
