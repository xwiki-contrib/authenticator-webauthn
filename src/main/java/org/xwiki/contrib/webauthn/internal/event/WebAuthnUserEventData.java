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
package org.xwiki.contrib.webauthn.internal.event;

import com.xpn.xwiki.doc.XWikiDocument;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;

import lombok.Value;

/**
 * Data sent with WebAuthn related events
 */
@Value
public class WebAuthnUserEventData
{

    RegisteredCredential credential;

    UserIdentity userIdentity;

    ByteArray publicKeyCose;

    int signatureCount;

    /**
     * Instantiates a new WebAuthn user event related data.
     *
     * @param credential the credential
     * @param userIdentity the user identity
     * @param publicKeyCose the public key cose
     * @param signatureCount the signature count
     */
    public WebAuthnUserEventData(RegisteredCredential credential, UserIdentity userIdentity,
        ByteArray publicKeyCose, int signatureCount)
    {
        this.credential = credential;
        this.userIdentity = userIdentity;
        this.publicKeyCose = publicKeyCose;
        this.signatureCount = signatureCount;
    }

    /**
     * Gets credential.
     *
     * @return the credential
     */
    public RegisteredCredential getCredential()
    {
        return credential;
    }

    /**
     * Gets user identity.
     *
     * @return the user identity
     */
    public UserIdentity getUserIdentity()
    {
        return userIdentity;
    }

    /**
     * Gets public key cose.
     *
     * @return the public key cose
     */
    public ByteArray getPublicKeyCose()
    {
        return publicKeyCose;
    }

    /**
     * Gets signature count.
     *
     * @return the signature count
     */
    public int getSignatureCount()
    {
        return signatureCount;
    }

}