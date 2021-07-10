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
import org.xwiki.contrib.webauthn.internal.WEBAUTHNResourceReference;

import com.onelogin.saml2.http.HttpRequest;

/**
 * Registration finish endpoint for WEBAUTHN
 *
 * @version $Id$
 */
@Component
@Named(WEBAUTHNRegistrationFinishEndpoint.HINT)
@Singleton
public class WEBAUTHNRegistrationFinishEndpoint implements WEBAUTHNEndpoint
{
    // Name of the endpoint: http://server/xwiki/webauthn/registration/finish
    public static final String HINT = "registration/finish";

    @Inject
    private Logger logger;

    /**
     * PLAN
     *
     * After receiving the response from the client, construct a PublicKeyCredential<AuthenticatorAttestationResponse,
     * ClientRegistrationExtensionOutputs> from the response and wrap that in a FinishRegistrationOptions along
     * with the PublicKeyCredentialCreationOptions used to initiate the request. Pass that as the argument to
     * RelyingParty.finishRegistration(FinishRegistrationOptions), which will return a RegistrationResult if successful
     * and throw an exception if not. Regardless of whether it succeeds, you should remove the
     * PublicKeyCredentialCreationOptions from the pending requests storage to prevent retries.
     * Finally, use the RegistrationResult to update any database(s) and take other actions
     * depending on your application's needs. In particular:
     * Store the keyId and publicKeyCose as a new credential for the user.
     * The CredentialRepository will need to look these up for authentication.
     * Inspect the warnings - ideally there should of course be none.
     * If you care about authenticator attestation, use the attestationTrusted, attestationType and
     * attestationMetadata fields to enforce your attestation policy.
     * If you care about authenticator attestation, it is recommended to also store the raw attestation object as
     * part of the credential. This enables you to retroactively inspect credential attestations in response to
     * policy changes and/or compromised authenticators.
     */
    @Override
    public Response handle(HttpRequest request, WEBAUTHNResourceReference reference) throws Exception
    {
        this.logger.debug("WEBAUTHN: Entering endpoint to finish registration");

        // Continue and finish the registration of webauthn credentials for an xwiki user here
        // the "finish" methods expect a pair of such a request object and the response object returned
        // from the browser. These methods perform all the verification logic specified by Web Authentication,
        // but it is your responsibility as the library user to store pending requests and act upon the returned results
        // - including enforcing policies and updating databases.

        return null;
    }
}
