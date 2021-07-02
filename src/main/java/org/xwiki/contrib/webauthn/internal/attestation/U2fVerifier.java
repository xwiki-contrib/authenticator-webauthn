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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.xwiki.contrib.webauthn.internal.data.RegistrationRequest;
import org.xwiki.contrib.webauthn.internal.data.U2fRegistrationResponse;

import org.xwiki.contrib.webauthn.internal.util.Crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.extension.appid.AppId;

/**
 * Get Challenge and verify it
 *
 * @version $Id$
 */
public class U2fVerifier
{
    public static boolean verify(
        AppId appId, RegistrationRequest request, U2fRegistrationResponse response)
        throws CertificateException, IOException, Base64UrlException
    {
        final ByteArray appIdHash = Crypto.sha256(appId.getId());

        final ByteArray clientDataHash =
            Crypto.sha256(response.getCredential().getU2fResponse().getClientDataJSON());

        final JsonNode clientData =
            JacksonCodecs.json()
                .readTree(response.getCredential().getU2fResponse().getClientDataJSON().getBytes());

        final String challengeBase64 = clientData.get("challenge").textValue();

        ExceptionUtil.assure(
            request
                .getPublicKeyCredentialCreationOptions()
                .getChallenge()
                .equals(ByteArray.fromBase64Url(challengeBase64)),
            "Wrong challenge.");

        InputStream attestationCertAndSignatureStream =
            new ByteArrayInputStream(
                response.getCredential().getU2fResponse().getAttestationCertAndSignature().getBytes());

        final X509Certificate attestationCert = CertificateParser.parseDer(attestationCertAndSignatureStream);

        byte[] signatureBytes = new byte[attestationCertAndSignatureStream.available()];

        attestationCertAndSignatureStream.read(signatureBytes);

        final ByteArray signature = new ByteArray(signatureBytes);

        return new U2fRawRegisterResponse(
            response.getCredential().getU2fResponse().getPublicKey(),
            response.getCredential().getU2fResponse().getKeyHandle(),
            attestationCert,
            signature)
            .verifySignature(appIdHash, clientDataHash);
    }
}