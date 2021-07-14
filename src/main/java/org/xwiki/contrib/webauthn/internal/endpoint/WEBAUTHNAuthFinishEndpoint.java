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
 * Authentication finish endpoint for WebAuthn
 *
 * @version $Id$
 */
@Component
@Named(WebAuthnAuthFinishEndpoint.HINT)
@Singleton
public class WebAuthnAuthFinishEndpoint implements WebAuthnEndpoint
{
    // Name of the endpoint: http://server/xwiki/webauthn/assertion/finish
    public static final String HINT = "assertion/finish";

    @Inject
    private Logger logger;

    /**
     * PLAN
     *
     * After receiving the response from the client, construct a PublicKeyCredential<AuthenticatorAssertionResponse,
     * ClientAssertionExtensionOutputs> from the response and wrap that in a FinishAssertionOptions along with the
     * AssertionRequest used to initiate the request. Pass that as the argument to RelyingParty.finishAssertion
     * (com.yubico.webauthn.FinishAssertionOptions), which will return an AssertionResult if successful and throw an
     * exception if not. Regardless of whether it succeeds, you should remove the AssertionRequest from the pending
     * requests storage to prevent retries. Finally, use the AssertionResult to update any database(s) and take other
     * actions depending on your application's needs. In particular: Use the username and/or userHandle results to
     * initiate a user session. Update the stored signature count for the credential (identified by the credentialId
     * result) to equal the value returned in the signatureCount result. Inspect the warnings - ideally there should
     * of course be none.
     */

    @Override
    public Response handle(HttpRequest request, WebAuthnResourceReference reference) throws Exception
    {
        this.logger.debug("WebAuthn: Entering endpoint for finishing assertion for authentication");

        // Continue and finish the assertion here
        // the "finish" methods expect a pair of such a request object and the response object returned
        // from the browser.  These methods perform all the verification logic specified by Web Authentication,
        // but it is your responsibility as the library user to store pending requests and act upon the returned results
        // - including enforcing policies and updating databases.
        return null;
    }
}
