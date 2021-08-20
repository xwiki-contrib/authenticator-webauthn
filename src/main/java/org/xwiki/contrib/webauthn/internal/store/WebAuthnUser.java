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
package org.xwiki.contrib.webauthn.internal.store;

import java.util.Arrays;

import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.objects.BaseObject;

/**
 * To manipulate WebAuthn metadata stored in a user profile.
 *
 * @version $Id$
 */
public class WebAuthnUser
{
    /**
     * The String reference of the class defining the object which contains the WebAuthn credential's
     * metadata in the user profile.
     */
    public static final String CLASS_FULLNAME = "XWiki.WebAuthn.UserCredentialClass";

    /**
     * The reference of the class defining the object which contains the WebAuthn credential's metadata in the
     * user profile.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "WebAuthn"), "UserCredentialClass");


    /**
     * The name of the property containing the WebAuthn user's credential ID.
     */
    public static final String FIELD_CREDENTIALID = "credentialId";

    /**
     * The name of the property containing the WebAuthn user's user ID.
     */
    public static final String FIELD_USERID = "userId";

    /**
     * The name of the property containing the WebAuthn user's public-key encoded in COSE_Key format.
     */
    public static final String FIELD_PUBLICKEYCOSE = "publicKeyCose";

    /**
     * The name of the property containing the WebAuthn user's number of successful assertions.
     */
    public static final String FIELD_SIGNATURECOUNT = "signatureCount";

    private final BaseObject xobject;

    /**
     * @param xobject the actual XWiki object
     */
    public WebAuthnUser(BaseObject xobject)
    {
        this.xobject = xobject;
    }

    /**
     * @return the WebAuthn user's credentialId.
     */
    public String getCredentialId()
    {
        return this.xobject.getStringValue(FIELD_CREDENTIALID);
    }

    /**
     * @param credentialId the WebAuthn user's credentialId.
     */
    public void setCredentialId(String credentialId)
    {
        this.xobject.setStringValue(FIELD_CREDENTIALID, credentialId);
    }

    /**
     * @return the WebAuthn user's userId.
     */
    public String getUserId()
    {
        return this.xobject.getStringValue(FIELD_USERID);
    }

    /**
     * @param userId the WebAuthn user's userId.
     */
    public void setUserId(String userId)
    {
        this.xobject.setStringValue(FIELD_USERID, userId);
    }

    /**
     * @return the WebAuthn user's userId.
     */
    public String getPublicKeyCose()
    {
        return this.xobject.getStringValue(FIELD_PUBLICKEYCOSE);
    }

    /**
     * @param publicKeyCose the WebAuthn user's publicKeyCose.
     */
    public void setPublicKeyCose(String publicKeyCose)
    {
        this.xobject.setStringValue(FIELD_PUBLICKEYCOSE, publicKeyCose);
    }

    /**
     * @return the WebAuthn user's signature count.
     */
    public String getSignatureCount()
    {
        return this.xobject.getStringValue(FIELD_SIGNATURECOUNT);
    }

    /**
     * @param signatureCount the WebAuthn user's signature count.
     */
    public void setSignatureCount(String signatureCount)
    {
        this.xobject.setIntValue(FIELD_SIGNATURECOUNT, Integer.parseInt(signatureCount));
    }
}