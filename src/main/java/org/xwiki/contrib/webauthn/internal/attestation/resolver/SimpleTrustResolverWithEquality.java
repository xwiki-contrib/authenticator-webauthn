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
package org.xwiki.contrib.webauthn.internal.attestation.resolver;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.webauthn.attestation.TrustResolver;

/**
 * Resolves a metadata object whose associated certificate has signed the argument certificate,
 * or is equal to the argument certificate.
 *
 * @version $Id$
 */
public class SimpleTrustResolverWithEquality implements TrustResolver
{
    private final SimpleTrustResolver subresolver;

    private final Multimap<String, X509Certificate> trustedCerts = ArrayListMultimap.create();

    public SimpleTrustResolverWithEquality(Collection<X509Certificate> trustedCertificates)
    {
        subresolver = new SimpleTrustResolver(trustedCertificates);

        for (X509Certificate cert : trustedCertificates) {
            trustedCerts.put(cert.getSubjectDN().getName(), cert);
        }
    }

    @Override
    public Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate, List<X509Certificate> caCertificateChain)
    {
        Optional<X509Certificate> subResult = subresolver.resolveTrustAnchor(attestationCertificate, caCertificateChain);

        if (subResult.isPresent()) {
            return subResult;
        } else {
            for (X509Certificate cert : trustedCerts.get(attestationCertificate.getSubjectDN().getName())) {
                if (cert.equals(attestationCertificate)) {
                    return Optional.of(cert);
                }
            }

            return Optional.empty();
        }
    }
}
