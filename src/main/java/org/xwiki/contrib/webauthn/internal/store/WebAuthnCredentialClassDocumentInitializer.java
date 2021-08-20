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
        xclass.addTextField(WebAuthnUser.FIELD_CREDENTIALID, "Credential ID", 60);
        xclass.addTextField(WebAuthnUser.FIELD_USERID, "User ID", 60);
        xclass.addTextAreaField(WebAuthnUser.FIELD_PUBLICKEYCOSE, "PublicKeyCOSE", 60, 10);
        xclass.addNumberField(WebAuthnUser.FIELD_SIGNATURECOUNT, "Signature Count", 100, INTEGER);
    }
}
