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
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;

/**
 * WebAuthn based configurations
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

    private static final Logger LOGGER = LoggerFactory.getLogger(WebAuthnConfiguration.class);

    @Inject
    private WebAuthnManager manager;

    @Inject
    protected ConfigurationSource configuration;

    @Inject
    private Container container;

    @Inject
    private ConverterManager converter;

    private static final String DEFAULT_ORIGIN = "https://localhost:8080";

    private static final int DEFAULT_PORT = 8080;

    private static final RelyingPartyIdentity DEFAULT_RP_ID =
        RelyingPartyIdentity.builder().id("localhost").name("XWiki WebAuthn Authenticator").build();

    private final Set<String> origins;

    private final int port;

    private final RelyingPartyIdentity rpIdentity;

    private final Optional<AppId> appId;

    private WebAuthnConfiguration(
        Set<String> origins, int port, RelyingPartyIdentity rpIdentity, Optional<AppId> appId)
    {
        this.origins = CollectionUtil.immutableSet(origins);
        this.port = port;
        this.rpIdentity = rpIdentity;
        this.appId = appId;
    }

    private static WebAuthnConfiguration instance;

    private static WebAuthnConfiguration getInstance()
    {
        if (instance == null) {
            try {
                instance = new WebAuthnConfiguration(computeOrigins(), computePort(), computeRpIdentity(), computeAppId());
            } catch (MalformedURLException | InvalidAppIdException e) {
                throw new RuntimeException(e);
            }
        }
        return instance;
    }

    public static Set<String> getOrigins()
    {
        return getInstance().origins;
    }

    public static int getPort()
    {
        return getInstance().port;
    }

    public static RelyingPartyIdentity getRpIdentity()
    {
        return getInstance().rpIdentity;
    }

    public static Optional<AppId> getAppId()
    {
        return getInstance().appId;
    }

    private static Set<String> computeOrigins()
    {
        final String origins = System.getenv("XWIKI_WEBAUTHN_ALLOWED_ORIGINS");

        LOGGER.debug("XWIKI_WEBAUTHN_ALLOWED_ORIGINS: {}", origins);

        final Set<String> result;

        if (origins == null) {
            result = Collections.singleton(DEFAULT_ORIGIN);
        } else {
            result = new HashSet<>(Arrays.asList(origins.split(",")));
        }

        LOGGER.info("Origins: {}", result);

        return result;
    }

    private static int computePort()
    {
        final String port = System.getenv("XWIKI_WEBAUTHN_PORT");

        if (port == null) {
            return DEFAULT_PORT;
        } else {
            return Integer.parseInt(port);
        }
    }

    private static RelyingPartyIdentity computeRpIdentity() throws MalformedURLException
    {
        final String name = System.getenv("XWIKI_WEBAUTHN_RP_NAME");
        final String id = System.getenv("XWIKI_WEBAUTHN_RP_ID");
        final String icon = System.getenv("XWIKI_WEBAUTHN_RP_ICON");

        LOGGER.debug("Relying Party name: {}", name);
        LOGGER.debug("Relying Party ID: {}", id);
        LOGGER.debug("Relying Party icon: {}", icon);

        RelyingPartyIdentity.RelyingPartyIdentityBuilder resultBuilder = DEFAULT_RP_ID.toBuilder();

        if (name == null) {
            LOGGER.debug("Relying Party name not given - using default.");
        } else {
            resultBuilder.name(name);
        }

        if (id == null) {
            LOGGER.debug("Relying Party ID not given - using default.");
        } else {
            resultBuilder.id(id);
        }

        if (icon == null) {
            LOGGER.debug("Relying Party icon not given - using none.");
        } else {
            try {
                resultBuilder.icon(Optional.of(new URL(icon)));
            } catch (MalformedURLException e) {
                LOGGER.error("Invalid icon URL: {}, icon URL: {}", icon, e);
                throw e;
            }
        }

        final RelyingPartyIdentity result = resultBuilder.build();

        LOGGER.info("Relying Party identity: {}", result);

        return result;
    }

    private static Optional<AppId> computeAppId() throws InvalidAppIdException
    {
        final String appId = System.getenv("YUBICO_WEBAUTHN_U2F_APPID");
        LOGGER.debug("YUBICO_WEBAUTHN_U2F_APPID: {}", appId);

        AppId result = appId == null ? new AppId("https://localhost:8443") : new AppId(appId);
        LOGGER.debug("U2F AppId: {}", result.getId());

        return Optional.of(result);
    }

    private HttpSession getHttpSessiongetHttpSession()
    {
        Session session = this.container.getSession();
        if (session instanceof ServletSession) {
            HttpSession httpSession = ((ServletSession) session).getHttpSession();
            LOGGER.debug("Session: {}", httpSession.getId());

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