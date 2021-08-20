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
import org.xwiki.properties.ConverterManager;

/**
 * WebAuthn based configurations
 *
 * @version $Id$
 */
@Component(roles = WebAuthnConfiguration.class)
@Singleton
public class WebAuthnConfiguration
{
    /**
     * The prefix used for WebAuthn configuration properties.
     */
    public static final String PREFIX_PROP = "webauthn.";

    public static final String PROP_XWIKIUSER = "webauthn.xwikiuser";

    public static final String PROP_INITIAL_REQUEST = "xwiki.initialRequest";

    public static final String PROP_SKIPPED = "webauthn.skipped";

    public static final String PROP_STATE = "webauthn.state";

    @Inject
    protected ConfigurationSource configuration;

    @Inject
    private Container container;

    @Inject
    private ConverterManager converter;

    @Inject
    private Logger logger;

    private HttpSession getHttpSession()
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


    /**
     * @param key the name of the property
     * @param valueClass the class of the property
     * @return the property value
     */
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

    /**
     * @param key the name of the property
     * @param def the default value
     * @return the property value
     */
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

    public String getSessionState()
    {
        return getSessionAttribute(PROP_STATE);
    }

    public String getWebAuthnUser()
    {
        return getSessionAttribute(PROP_XWIKIUSER);
    }

    public boolean isSkipped()
    {
        return getProperty(PROP_SKIPPED, false);
    }

    public URI getSuccessRedirectURI()
    {
        URI uri = getSessionAttribute(PROP_INITIAL_REQUEST);
        if (uri == null) {
            // TODO: return wiki home page
        }

        return uri;
    }

    public void setSuccessRedirectURI(URI uri)
    {
        setSessionAttribute(PROP_INITIAL_REQUEST, uri);
    }
}