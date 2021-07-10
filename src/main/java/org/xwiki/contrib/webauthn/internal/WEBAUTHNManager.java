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
package org.xwiki.contrib.webauthn.internal;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.container.Response;

import com.onelogin.saml2.servlet.ServletUtils;
import com.xpn.xwiki.XWikiContext;

/**
 * Main utility for WEBAUTHN
 *
 * @version $Id$
 */
@Component(roles = WEBAUTHNManager.class)
@Singleton
public class WEBAUTHNManager implements Initializable
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private WEBAUTHNConfiguration configuration;

    @Inject
    private Logger logger;


    @Override
    public void initialize() throws InitializationException
    {
    }

    /**
     * Generate and return an external {@link URI} for passed endpoint in the current instance.
     *
     * @param endpoint the endpoint
     * @return the {@link URI}
     * @throws MalformedURLException when failing to get server URL
     * @throws URISyntaxException when failing to create the URI
     */
    public URI createEndPointURI(String endpoint) throws MalformedURLException, URISyntaxException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        StringBuilder base = new StringBuilder();

        base.append(xcontext.getURLFactory().getServerURL(xcontext));

        if (base.charAt(base.length() - 1) != '/') {
            base.append('/');
        }

        String webAppPath = xcontext.getWiki().getWebAppPath(xcontext);
        if (!webAppPath.equals("/")) {
            base.append(webAppPath);
        }

        base.append("webauthn/");

        return createEndPointURI(base.toString(), endpoint);
    }

    /**
     * Generate and return an external {@link URI} for passed endpoint in the passed instance.
     *
     * @param base target instance
     * @param endpoint the endpoint
     * @return the {@link URI}
     * @throws URISyntaxException when failing to create the URI
     */
    public URI createEndPointURI(String base, String endpoint) throws URISyntaxException
    {
        StringBuilder uri = new StringBuilder(base);

        if (!base.endsWith("/")) {
            uri.append('/');
        }

        uri.append(endpoint);

        return new URI(uri.toString());
    }
}
