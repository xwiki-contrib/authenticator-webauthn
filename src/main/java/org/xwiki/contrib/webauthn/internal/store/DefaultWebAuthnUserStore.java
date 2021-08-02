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
@Component
@Singleton
public class DefaultWebAuthnUserStore implements WebAuthnUserStore
{
    @Inject
    private QueryManager queries;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> resolver;

    @Override public boolean updateWebAuthnUser(XWikiDocument userDocument, String username, String userhandle,
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

    @Override
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
