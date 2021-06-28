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

import java.time.Instant;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.UserIdentity;
import lombok.Builder;
import lombok.Value;
import lombok.With;

/**
 * Properties associated with a WebAuthn credential
 *
 * @version $Id$
 */
@Value
@Builder
@With
public class CredentialRegistration
{

    long signatureCount;

    UserIdentity userIdentity;

    Optional<String> credentialNickname;

    @JsonIgnore
    Instant registrationTime;

    RegisteredCredential credential;

    Optional<Attestation> attestationMetadata;

    @JsonProperty("registrationTime")
    public String getRegistrationTimestamp()
    {
        return registrationTime.toString();
    }

    public String getUsername()
    {
        return userIdentity.getName();
    }
}
