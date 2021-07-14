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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.Session;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnAuthFinishEndpoint;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnAuthStartEndpoint;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnEndpoint;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnLogoutEndpoint;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnRegistrationFinishEndpoint;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnRegistrationStartEndpoint;
import org.xwiki.properties.ConverterManager;

/**
 * WebAuthn based configuration
 *
 * @version $Id$
 */
@Singleton
@Component(roles = WebAuthnConfiguration.class)
public class WebAuthnConfiguration
{
    /**
     * The prefix used for WebAuthn configuration properties.
     */
    public static final String PREFIX_PROP = "webauthn.";

    public static final String PROPPREFIX_ENDPOINT = "webauthn.endpoint.";

    public static final String PROP_ENDPOINT_START_REGISTER = PROPPREFIX_ENDPOINT +
        "WebAuthnRegistrationStartEndpoint.HINT";

    public static final String PROP_ENDPOINT_FINISH_REGISTER = PROPPREFIX_ENDPOINT +
        "WebAuthnRegistrationFinishEndpoint.HINT";

    public static final String PROP_ENDPOINT_START_AUTH = PROPPREFIX_ENDPOINT +
        "WebAuthnAuthStartEndpoint.HINT";

    public static final String PROP_ENDPOINT_FINISH_AUTH = PROPPREFIX_ENDPOINT +
        "WebAuthnAuthFinishEndpoint.HINT";

    public static final String PROP_SKIPPED = "webauthn.skipped";

    @Inject
    private WebAuthnManager manager;

    @Inject
    private Logger logger;

    @Inject
    protected ConfigurationSource configuration;

    @Inject
    private Container container;

    @Inject
    private ConverterManager converter;


    private HttpSession getHttpSessiongetHttpSession()
    {
        Session session = this.container.getSession();
        if (session instanceof ServletSession) {
            HttpSession httpSession = ((ServletSession) session).getHttpSession();

            this.logger.debug("Session: {}", httpSession.getId());

            return httpSession;
        }

        return null;
    }

    private <T> T getSessionAttribute(String name)
    {
        HttpSession session = getHttpSession();
        if (session != null) {
            return (T) session.getAttribute(name);
        }

        return null;
    }

    private HttpSession getHttpSession()
    {
        return null;
    }

    private <T> T removeSessionAttribute(String name)
    {
        HttpSession session = getHttpSession();
        if (session != null) {
            try {
                return (T) session.getAttribute(name);
            } finally {
                session.removeAttribute(name);
            }
        }

        return null;
    }

    private void setSessionAttribute(String name, Object value)
    {
        HttpSession session = getHttpSession();
        if (session != null) {
            session.setAttribute(name, value);
        }
    }

    private String getRequestParameter(String key)
    {
        Request request = this.container.getRequest();
        if (request != null) {
            return (String) request.getProperty(key);
        }

        return null;
    }

    public Map<String, String> getMap(String key)
    {
        List<String> list = getProperty(key, List.class);

        Map<String, String> mapping;

        if (list != null && !list.isEmpty()) {
            mapping = new HashMap<>(list.size());

            for (String listItem : list) {
                int index = listItem.indexOf('=');

                if (index != -1) {
                    mapping.put(listItem.substring(0, index), listItem.substring(index + 1));
                }
            }
        } else {
            mapping = null;
        }

        return mapping;
    }


    protected <T> T getProperty(String key, Class<T> valueClass)
    {
        // Get property from request
        String requestValue = getRequestParameter(key);
        if (requestValue != null) {
            return this.converter.convert(valueClass, requestValue);
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get property from configuration
        return this.configuration.getProperty(key, valueClass);
    }


    protected <T> T getProperty(String key, T def)
    {
        // Get property from request
        String requestValue = getRequestParameter(key);
        if (requestValue != null) {
            return this.converter.convert(def.getClass(), requestValue);
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get property from configuration
        return this.configuration.getProperty(key, def);
    }

    private WebAuthnEndpoint getEndPoint(String hint) throws URISyntaxException
    {
        String uriString = getProperty(PROPPREFIX_ENDPOINT + hint, String.class);

        // Placeholders
        URI uri;
        if (uriString == null) {
            if (getProperty("1", String.class) != null) {
                uri = this.manager.createEndPointURI(getXWikiProvider().toString(), hint);
            } else {
                uri = null;
            }
        } else {
            uri = new URI(uriString);
        }

        // If we still don't have any endpoint URI, return null
        if (uri == null) {
            return null;
        }

        // Find custom headers
        Map<String, List<String>> headers = new LinkedHashMap<>();

        List<String> entries = getProperty(PROPPREFIX_ENDPOINT + hint + ".headers", List.class);
        if (entries != null) {
            for (String entry : entries) {
                int index = entry.indexOf(':');

                if (index > 0 && index < entry.length() - 1) {
                    headers.computeIfAbsent(entry.substring(0, index), key -> new ArrayList<>())
                        .add(entry.substring(index + 1));
                }
            }
        }

        return (httpRequest, reference) -> null;
    }

    // Placeholder
    private Object getXWikiProvider()
    {
        return null;
    }

    public WebAuthnEndpoint getWebAuthnRegistrationStartEndpoint() throws URISyntaxException
    {
        return getEndPoint(WebAuthnRegistrationStartEndpoint.HINT);
    }

    public WebAuthnEndpoint getWebAuthnRegistrationFinishEndpoint() throws URISyntaxException
    {
        return getEndPoint(WebAuthnRegistrationFinishEndpoint.HINT);
    }

    public WebAuthnEndpoint getWebAuthnAuthStartEndpoint() throws URISyntaxException
    {
        return getEndPoint(WebAuthnAuthStartEndpoint.HINT);
    }

    public WebAuthnEndpoint getWEBAUTHNAuthFinishEndpoint() throws URISyntaxException
    {
        return getEndPoint(WebAuthnAuthFinishEndpoint.HINT);
    }

    public WebAuthnEndpoint getWebAuthnLogoutEndpoint() throws URISyntaxException
    {
        return getEndPoint(WebAuthnLogoutEndpoint.HINT);
    }

    public boolean isSkipped()
    {
        return getProperty(PROP_SKIPPED, false);
    }
}