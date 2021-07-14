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
package org.xwiki.contrib.webauthn.internal.endpoint;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Response;
import org.xwiki.contrib.webauthn.internal.WebAuthnResourceReference;

import com.onelogin.saml2.http.HttpRequest;

/**
 * Authentication start endpoint for WebAuthn
 *
 * @version $Id$
 */
@Component
@Named(WebAuthnAuthStartEndpoint.HINT)
@Singleton
public class WebAuthnAuthStartEndpoint implements WebAuthnEndpoint
{
    // Name of the endpoint: http://server/xwiki/webauthn/assertion
    public static final String HINT = "assertion";

    @Inject
    private Logger logger;

    /**
     * PLAN
     *
     * The startAssertion method returns an AssertionRequest containing the username, if any, and a
     * PublicKeyCredentialRequestOptions instance which can be serialized to JSON and passed as the
     * publicKey argument to navigator.credentials.get(). Again, store the AssertionRequest in
     * temporary storage so it can be passed as an argument to
     * RelyingParty.finishAssertion(com.yubico.webauthn.FinishAssertionOptions).
     *
     */
    @Override
    public Response handle(HttpRequest request, WebAuthnResourceReference reference) throws Exception
    {
        this.logger.debug("WebAuthn: Starting assertion for authentication");

        // Start the assertion here
        // The "start" methods return request objects containing the parameters to be used in the call
        // to navigator.credentials.get()
        return null;
    }
}
