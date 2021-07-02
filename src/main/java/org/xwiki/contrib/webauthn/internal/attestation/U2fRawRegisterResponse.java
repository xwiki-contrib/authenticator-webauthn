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
package org.xwiki.contrib.webauthn.internal.attestation;

import java.security.cert.X509Certificate;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import org.xwiki.contrib.webauthn.internal.util.Crypto;

import lombok.Value;

/**
 * The register response produced by the token/key
 *
 * @version $Id$
 */
@Value
class U2fRawRegisterResponse
{
    private static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;

    /**
     * The (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
     **/
    private final ByteArray userPublicKey;

    /**
     * A handle that allows the U2F token to identify the generated key pair.
     **/
    private final ByteArray keyHandle;

    private final X509Certificate attestationCertificate;

    /**
     * A ECDSA signature (on P-256)
     **/
    private final ByteArray signature;

    U2fRawRegisterResponse(ByteArray userPublicKey, ByteArray keyHandle,
        X509Certificate attestationCertificate, ByteArray signature)
    {
        this.userPublicKey = userPublicKey;
        this.keyHandle = keyHandle;
        this.attestationCertificate = attestationCertificate;
        this.signature = signature;
    }

    boolean verifySignature(ByteArray appIdHash, ByteArray clientDataHash)
    {
        ByteArray signedBytes = packBytesToSign(appIdHash, clientDataHash, keyHandle, userPublicKey);

        return Crypto.verifySignature(attestationCertificate, signedBytes, signature, COSEAlgorithmIdentifier.ES256);
    }

    private static ByteArray packBytesToSign(
        ByteArray appIdHash, ByteArray clientDataHash, ByteArray keyHandle, ByteArray userPublicKey)
    {
        ByteArrayDataOutput encoded = ByteStreams.newDataOutput();

        encoded.write(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE);

        encoded.write(appIdHash.getBytes());

        encoded.write(clientDataHash.getBytes());

        encoded.write(keyHandle.getBytes());

        encoded.write(userPublicKey.getBytes());

        return new ByteArray(encoded.toByteArray());
    }
}
