package org.xwiki.contrib.webauthn.internal.store;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;

/**
 * Initialize WebAuthn credential class for WebAuthn user.
 *
 * @version $Id$
 */
@Component
@Named(WebAuthnUser.CLASS_FULLNAME)
@Singleton
public class WebAuthnCredentialClassDocumentInitializer extends AbstractMandatoryClassInitializer
{
    private static final String INTEGER = "integer";

    /**
     * Default constructor.
     */
    public WebAuthnCredentialClassDocumentInitializer()
    {
        super(WebAuthnUser.CLASS_REFERENCE, "WebAuthn User Credentials Class");
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(WebAuthnUser.FIELD_USERNAME, "Username", 30);
        xclass.addTextField(WebAuthnUser.FIELD_USERHANDLE, "User Handle", 60);
        xclass.addTextField(WebAuthnUser.FIELD_CREDENTIALID, "Credential ID", 60);
        xclass.addTextField(WebAuthnUser.FIELD_USERID, "User Handle", 60);
        xclass.addTextField(WebAuthnUser.FIELD_PUBLICKEYCOSE, "PublicKeyCOSE", 400);
        xclass.addNumberField(WebAuthnUser.FIELD_SIGNATURECOUNT, "Signature Count", 100, INTEGER);
    }
}
