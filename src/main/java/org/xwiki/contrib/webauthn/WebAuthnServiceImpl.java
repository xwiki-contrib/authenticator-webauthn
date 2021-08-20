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
package org.xwiki.contrib.webauthn;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.container.servlet.filters.SavedRequestManager;
import org.xwiki.contrib.webauthn.internal.WebAuthn;
import org.xwiki.contrib.webauthn.internal.WebAuthnConfiguration;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Authenticate a user using WebAuthn authenticator
 *
 * @version $Id$
 */
public class WebAuthnServiceImpl extends XWikiAuthServiceImpl
{
    private static final Logger LOGGER = LoggerFactory.getLogger(WebAuthnServiceImpl.class);

    private static final String WEBAUTHN_SRID = "webauthn.srid";

    private WebAuthnConfiguration configuration = Utils.getComponent(WebAuthnConfiguration.class);

    //private WebAuthnRegistrationManager users = Utils.getComponent(WebAuthnRegistrationManager.class);

    private WebAuthn manager = Utils.getComponent(WebAuthn.class);


    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        LOGGER.debug("Checking if a user already exists");
        // Check if there is already a user in the session, take care of logout, etc.
        XWikiUser user = super.checkAuth(context);

        // Try WebAuthn if there is no already authenticated user
        if (user == null) {
            try {
                checkAuthWebAuthn(context);
            } catch (Exception e) {
                throw new XWikiException("Authentication via WebAuthn failed.", e);
            }
        } else {
            // TODO: Check if we need to update something
        }

        return user;
    }

    private void checkAuthWebAuthn(XWikiContext context) throws Exception
    {
        LOGGER.debug("Checking if WebAuthn was skipped");

        // Check if WebAuthn is skipped or not and remember it
        if (this.configuration.isSkipped()) {
            maybeStoreRequestParameterInSession(context.getRequest(), WebAuthnConfiguration.PROP_SKIPPED,
                Boolean.class);

            return;
        } else {
            maybeStoreRequestParameterInSession(context.getRequest(), WebAuthnConfiguration.PROP_SKIPPED,
                Boolean.class);
        }

        // Make sure the session is free from anything related to a previously authenticated user
        // in case we just did a logout
        if(this.configuration.getWebAuthnUser() != null) {
            // this.users.logout();
        }

        // authenticate the WebAuthn user
        String webauthnUser = context.getRequest().getParameter(WebAuthnConfiguration.PROP_XWIKIUSER);
        if (webauthnUser != null) {
            authenticate(context);

            return;
        }

        // Call WebAuthn Authenticator when someone requests to login
        if (context.getAction().equals("login")) {
            showLoginWebAuthn(context);
        }
    }


    private void showLoginWebAuthn(XWikiContext context) throws Exception
    {
        // Check endpoints for authentication
        LOGGER.debug("Show the login screen to the user");

        // Save the request to not loose sent content
        String savedRequestId = handleSavedRequest(context);

        this.manager.executeTemplate("webauthn/client/provider.vm", context.getResponse());

        context.setFinished(true);
    }

    private void authenticate(XWikiContext context) throws URISyntaxException, IOException
    {
        // Save the request to not loose sent content
        String savedRequestId = handleSavedRequest(context);

        authenticate(savedRequestId, context);
    }

    private void authenticate(String savedRequestId, XWikiContext context) throws URISyntaxException, IOException
    {
        // Remember various stuff in the session so that callback can access it
        XWikiRequest request = context.getRequest();

    }

    private String getSavedRequestIdentifier(XWikiRequest request)
    {
        String savedRequestId = request.getParameter(SavedRequestManager.getSavedRequestIdentifier());
        if (savedRequestId == null) {
            savedRequestId = request.getParameter(WEBAUTHN_SRID);
        }

        return savedRequestId;
    }

    private String handleSavedRequest(XWikiContext xcontext)
    {
        XWikiRequest request = xcontext.getRequest();
        String savedRequestId = getSavedRequestIdentifier(request);
        if (StringUtils.isEmpty(savedRequestId)) {
            // Save the request to not loose sent content
            savedRequestId = SavedRequestManager.saveRequest(request);
        }

        return savedRequestId;
    }

    // Maybe useful in future(maybeStoreRequestParameterInSession), will remove if not
    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key,
        Class<Boolean> booleanClass)
    {
        String value = request.get(key);
        this.LOGGER.debug("Store the request parameter in session");
        if (value != null) {
            request.getSession().setAttribute(key, value);
        }
    }


    private void maybeStoreRequestParameterURLInSession(XWikiRequest request, String key) throws MalformedURLException
    {
        String value = request.get(key);

        if (value != null) {
            request.getSession().setAttribute(key, new URL(value));
        }
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        // If WebAuthn is not skipped and we can't authenticate user, throw error
        LOGGER.debug("Show the login screen to the user");

        if (!this.configuration.isSkipped()) {
            try {
                showLoginWebAuthn(context);
            } catch (Exception e) {
                LOGGER.error("Failed to show WEBAUTHN login", e);

                // Fallback on standard auth
                super.showLogin(context);
            }
        } else {
            super.showLogin(context);
        }
    }
}
