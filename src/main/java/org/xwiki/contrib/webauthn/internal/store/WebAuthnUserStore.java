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

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Helper to manage WebAuthn user profile's XClass and XObject.
 *
 * @version $Id$
 */
@Component(roles = WebAuthnUserStore.class)
@Singleton
public class WebAuthnUserStore
{
    @Inject
    private QueryManager queries;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    /**
     * Add or update WebAuthn metadata in the user profile
     *
     * @param userDocument the document in which the WebAuthn user is stored
     * @param username the WebAuthn user's username.
     * @param userhandle the WebAuthn user's userhandle.
     * @param credentialId the WebAuthn user's credentialId.
     * @param userId the WebAuthn user's userId.
     * @param publicKeyCose the WebAuthn user's publicKeyCose.
     * @param signatureCount the WebAuthn user's signature count.
     **/
    public boolean updateWebAuthnUser(XWikiDocument userDocument, String username, String userhandle,
        String credentialId, String userId, String publicKeyCose, String signatureCount)
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        WebAuthnUser user = new WebAuthnUser(userDocument.getXObject(WebAuthnUser.CLASS_REFERENCE, true, xcontext));

        boolean needUpdate = false;

        if (!StringUtils.equals(user.getUsername(), username)) {
            user.setUsername(username);
            needUpdate = true;
        }

        if (!StringUtils.equals(user.getUserhandle(), userhandle)) {
            user.setUserhandle(userhandle);
            needUpdate = true;
        }

        if (!StringUtils.equals(user.getCredentialId(), credentialId)) {
            user.setCredentialId(credentialId);
            needUpdate = true;
        }

        if (!StringUtils.equals(user.getUserId(), userId)) {
            user.setUserId(userId);
            needUpdate = true;
        }

        if (!StringUtils.equals(user.getPublicKeyCose(), publicKeyCose)) {
            user.setPublicKeyCose(publicKeyCose);
            needUpdate = true;
        }

        if (!StringUtils.equals(user.getSignatureCount(), signatureCount)) {
            user.setSignatureCount(signatureCount);
            needUpdate = true;
        }

        return needUpdate;
    }

    /**
     * Search in the existing XWiki user if one already has WebAuthn credentials associated with them
     *
     * @param username the WebAuthn user's username.
     * @param userhandle the WebAuthn user's userhandle.
     * @param credentialId the WebAuthn user's credentialId.
     * @param userId the WebAuthn user's userId.
     * @param publicKeyCose the WebAuthn user's publicKeyCose.
     * @param signatureCount the WebAuthn user's signature count.
     * @return the document of the user profile which already contains theses WebAuthn credentials
     * @throws XWikiException when failing the get the document
     * @throws QueryException when failing to search for the document
     */
    public XWikiDocument searchDocument(String username, String userhandle, String credentialId, String userId,
        String publicKeyCose, String signatureCount) throws XWikiException, QueryException
    {
        Query query = this.queries.createQuery("from doc.object(" + WebAuthnUser.CLASS_FULLNAME
            + ") as webauthn where webauthn.username = :username and webauthn.userhandle = :userhandle and webauthn"
            + ".credentialId = :credentialId and webauthn.userId = :userId and webauthn.publicKeyCose = "
            + ":publicKeyCose and webauthn.signatureCount = :signatureCount", Query.XWQL);

        query.bindValue("username", username);
        query.bindValue("userhandle", userhandle);
        query.bindValue("credentialId", credentialId);
        query.bindValue("userId", userId);
        query.bindValue("publicKeyCose", publicKeyCose);
        query.bindValue("signatureCount", signatureCount);

        List<String> documents = query.execute();

        if (documents.isEmpty()) {
            return null;
        }

        // TODO: throw exception when there are several credentials for a single username ?

        XWikiContext xcontext = this.xcontextProvider.get();

        DocumentReference userReference = this.resolver.resolve(documents.get(0));

        XWikiDocument userDocument = xcontext.getWiki().getDocument(userReference, xcontext);

        if (userDocument.isNew()) {
            return null;
        }

        return userDocument;
    }
}
