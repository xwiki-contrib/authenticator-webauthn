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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * The U2f registration result for a successful webauthn registration.
 *
 * @version $Id$
 */
@Value
@Builder
public class U2fRegistrationResult
{
    @NonNull PublicKeyCredentialDescriptor keyId;

    boolean attestationTrusted;

    @NonNull ByteArray publicKeyCose;

    @NonNull @Builder.Default List<String> warnings = Collections.emptyList();

    @NonNull @Builder.Default Optional<Attestation> attestationMetadata = Optional.empty();

    /**
     * Instantiates a new U2f registration result.
     *
     * @param keyId the credential ID of the created webauthn credentials
     * @param attestationTrusted the attestation is trusted? true or false
     * @param publicKeyCose the public-key credential encoded in COSE_Key format
     */
    public U2fRegistrationResult(@NonNull PublicKeyCredentialDescriptor keyId, boolean attestationTrusted,
        @NonNull ByteArray publicKeyCose)
    {
        this.keyId = keyId;
        this.attestationTrusted = attestationTrusted;
        this.publicKeyCose = publicKeyCose;
    }
}



