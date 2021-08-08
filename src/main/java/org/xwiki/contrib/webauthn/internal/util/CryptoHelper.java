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
package org.xwiki.contrib.webauthn.internal.util;

import com.google.common.hash.Hashing;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Values from
 * https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-
 * for-classified/algorithm-guidance/mathematical-routines-for-the-nist-prime-elliptic-curves.cfm
 * cross-referenced with "secp256r1" in https://www.secg.org/sec2-v2.pdf
 */
@UtilityClass
@Slf4j
public final class CryptoHelper
{
    private static final EllipticCurve P256 = new EllipticCurve(
        new ECFieldFp(
            new BigInteger(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)),
            new BigInteger(
                "115792089210356248762697446949407573530086143415290314195533631308867097853948", 10),
            new BigInteger(
                "41058363725152142129326129780047268409114441015993725554835256314039467401291", 10));


    private static class BouncyCastleLoader
    {
        private static Provider getProvider()
        {
            return new BouncyCastleProvider();
        }
    }

    public static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException
    {
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            log.debug("Caught {}. Attempting fallback to BouncyCastle...", e.toString());
            try {
                return KeyFactory.getInstance(algorithm, BouncyCastleLoader.getProvider());
            } catch (NoSuchAlgorithmException | NoClassDefFoundError e2) {
                throw e;
            }
        }
    }


    public static Signature getSignature(String algorithm) throws NoSuchAlgorithmException
    {
        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            log.debug("Caught {}. Attempting fallback to BouncyCastle...", e.toString());
            try {
                return Signature.getInstance(algorithm, BouncyCastleLoader.getProvider());
            } catch (NoSuchAlgorithmException | NoClassDefFoundError e2) {
                throw e;
            }
        }
    }

    static boolean isP256(ECParameterSpec params)
    {
        return P256.equals(params.getCurve());
    }

    public static boolean verifySignature(X509Certificate attestationCertificate, ByteArray signedBytes,
        ByteArray signature, COSEAlgorithmIdentifier alg)
    {
        return verifySignature(attestationCertificate.getPublicKey(), signedBytes, signature, alg);
    }

    public static boolean verifySignature(PublicKey publicKey, ByteArray signedBytes,
        ByteArray signatureBytes, COSEAlgorithmIdentifier alg)
    {
        try {
            Signature signature = Signature.getInstance(WebAuthnCosePublicKey.getJavaAlgorithmName(alg));
            signature.initVerify(publicKey);
            signature.update(signedBytes.getBytes());
            return signature.verify(signatureBytes.getBytes());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(
                String.format(
                    "Failed to verify signature. This could be a problem with your JVM environment, "
                        + "or a bug in webauthn-server-core. Public key: %s, signed data: %s , signature: %s",
                    publicKey, signedBytes.getBase64Url(), signatureBytes.getBase64Url()), e);
        }
    }

    public static ByteArray sha256(ByteArray bytes)
    {
        // No inspection UnstableApiUsage
        return new ByteArray(Hashing.sha256().hashBytes(bytes.getBytes()).asBytes());
    }

    public static ByteArray sha256(String str)
    {
        return sha256(new ByteArray(str.getBytes(StandardCharsets.UTF_8)));
    }
}