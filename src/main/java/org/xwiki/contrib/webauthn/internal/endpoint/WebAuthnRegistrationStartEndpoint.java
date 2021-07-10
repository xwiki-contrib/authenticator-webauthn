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
 * Registration start endpoint for WEBAUTHN
 *
 * @version $Id$
 */
@Component
@Named(WEBAUTHNRegistrationStartEndpoint.HINT)
@Singleton
public class WEBAUTHNRegistrationStartEndpoint implements WEBAUTHNEndpoint
{
    // Name of the endpoint: http://server/xwiki/webauthn/registration
    public static final String HINT = "registration";

    @Inject
    private Logger logger;

    /**
     * PLAN
     *
     * To initiate a registration operation, construct a StartRegistrationOptions instance using its builder and pass
     * that into RelyingParty.startRegistration(StartRegistrationOptions). The only required parameter is a UserIdentity
     * describing the user for which to create a credential. One noteworthy part of UserIdentity is the id field,
     * containing the user handle for the user. This should be a stable, unique identifier for the user - equivalent to
     * a username, in most cases. However, due to privacy considerations it is recommended to set the user handle to a
     * random byte array rather than, say, the username encoded in UTF-8. The startRegistration method returns a
     * PublicKeyCredentialCreationOptions which can be serialized to JSON and passed as the publicKey argument to
     * navigator.credentials.create(). You can use the toBuilder() method to make any modifications you need.
     * You should store this in temporary storage so that it can later be passed as an argument to
     * RelyingParty.finishRegistration(FinishRegistrationOptions).
     */
    @Override
    public Response handle(HttpRequest request, WEBAUTHNResourceReference reference) throws Exception
    {
        this.logger.debug("WEBAUTHN: Starting registration");

        // Start the registration of webauthn credentials here
        // The "start" methods return request objects containing the parameters to be used in the call
        // to navigator.credentials.create()
        return null;
    }
}
