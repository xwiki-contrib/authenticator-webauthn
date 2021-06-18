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
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.xwiki.context.Execution;

import com.xpn.xwiki.XWiki;
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

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        // Check if there is already a user in the session, take care of logout, etc.
        XWikiUser user = super.checkAuth(context);

        // Try WebAuthn if there is no already authenticated user
        if (user == null) {
            try {
                // checkAuthWebAuthn(context)
            } catch (Exception e) {
                // throw new XWikiException("Authentication via WebAuthn failed.", e);
            }
        } else {
            // Check if we need to update something
        }

        return user;
    }

    private void checkAuthWebAuthn(XWikiContext context) throws Exception
    {
        // Check if WebAuthn is skipped or not and remember it

        // Make sure the session is free from anything related to a previously authenticated user
        // in case we just did a logout

        // Call WebAuthn Authenticator when someone requests to login
    }


    private void showLoginWebAuthn(XWikiContext context) throws Exception
    {
        // Check endpoints for authentication

        // If no endpoint can be found, ask for it

        // Authenticate user
    }

    private void authenticate(XWikiContext context) throws Exception, URISyntaxException, IOException
    {
        // Generate authentication URL

        // Remember the current URL

        // Create the request URL

        // Redirect user to home if successfully authenticated
    }

    private ExecutionContext getExecutionContext()
    {
        Execution execution = Utils.getComponent(Execution.class);

        if (execution != null) {
            return execution.getContext();
        }

        return null;
    }

    // Maybe useful in future(maybeStoreRequestParameterInSession), will remove if not
    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key)
    {
        String value = request.get(key);

        if (value != null) {
            request.getSession().setAttribute(key, value);
        }
    }

    private void maybeStoreRequestParameterInSession(XWikiRequest request, String key, Type targetType)
    {
        String value = request.get(key);

        if (value != null) {
            request.getSession().setAttribute(key, this.converter.convert(targetType, value));
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

        // Fallback on standard auth
    }
}
