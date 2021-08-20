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
    /**
     * The number of successful authentications for a given {@link RegisteredCredential}
     */
    long signatureCount;

    /**
     * Describes a user account, with which public key credentials will be associated.
     *
     * @see <a
     *     href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialuserentity">§5.4.3.
     *     User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)
     *     </a>
     */
    UserIdentity userIdentity;

    Optional<String> credentialNickname;

    /**
     * The time at which registration was completed.
     */
    @JsonIgnore
    Instant registrationTime;

    /**
     * An abstraction of a credential registered to a given xwiki standard user.
     */
    RegisteredCredential credential;

    /**
     * Non-standardized representation of partly free-form information about an authenticator device.
     */
    Optional<Attestation> attestationMetadata;

    /**
     * @return the exact time stamp when the registration of credentials was completed
     */
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
