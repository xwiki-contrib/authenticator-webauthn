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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.resource.CreateResourceReferenceException;
import org.xwiki.resource.ResourceType;
import org.xwiki.resource.UnsupportedResourceReferenceException;
import org.xwiki.url.ExtendedURL;
import org.xwiki.url.internal.AbstractResourceReferenceResolver;

/**
 * Transform WebAuthn URL into a typed Resource Reference. The URL format handled is
 * {@code http://server/context/webauthn/}.
 *
 * @version $Id$
 */
@Component
@Named("webauthn")
@Singleton
public class WebAuthnResourceReferenceResolver extends AbstractResourceReferenceResolver
{
    @Override
    public WebAuthnResourceReference resolve(ExtendedURL extendedURL, ResourceType resourceType,
        Map<String, Object> parameters) throws CreateResourceReferenceException, UnsupportedResourceReferenceException
    {
        String path = "";
        String endpoint = "";

        List<String> pathSegments = extendedURL.getSegments();
        if (!pathSegments.isEmpty()) {
            StringBuilder pathBuilder = new StringBuilder();
            try {
                for (String pathSegment : extendedURL.getSegments()) {
                    if(pathBuilder.length() > 0) {
                        pathBuilder.append('/');
                    }
                    pathBuilder.append(URLEncoder.encode(pathSegment, "UTF8"));
                }
            } catch (UnsupportedEncodingException e) {
                // should never happen
            }

            path = pathBuilder.toString();
            endpoint = pathSegments.get(0);

            if(pathSegments.size() > 1) {
                pathSegments = pathSegments.subList(1, pathSegments.size());
            } else {
                pathSegments = Collections.emptyList();
            }
        }

        WebAuthnResourceReference reference = new WebAuthnResourceReference(path, endpoint, pathSegments);

        copyParameters(extendedURL, reference);

        return reference;
    }
}
