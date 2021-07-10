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

import java.util.List;

import org.xwiki.resource.AbstractResourceReference;
import org.xwiki.resource.ResourceType;

/**
 * Dummy type for WEBAUTHN entry point.
 *
 * @version $Id$
 */
public class WEBAUTHNResourceReference extends AbstractResourceReference
{
    /**
     * Represents a WEBAUTHN Resource Type.
     */
    public static final ResourceType TYPE = new ResourceType("webauthn");

    private String path;

    private String endpoint;

    private List<String> pathSegments;

    /**
     * Default constructor.
     *
     * @param path the path starting with the endpoint
     * @param endpoint the target endpoint
     * @param pathSegments the rest of the path
     */
    public WEBAUTHNResourceReference(String path, String endpoint, List<String> pathSegments)
    {
        setType(TYPE);
        this.path = path;
        this.endpoint = endpoint;
        this.pathSegments = pathSegments;
    }

    /**
     * @return the path starting with the endpoint
     */
    public String getPath()
    {
        return this.path;
    }

    /**
     * @return the endpoint
     */
    public String getEndpoint()
    {
        return this.endpoint;
    }

    /**
     * @return the endpoint path (elements after the endpoint)
     */
    public List<String> getPathSegments()
    {
        return this.pathSegments;
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();

        builder.append("path = ");
        builder.append(getPath());
        builder.append(", endpoint = ");
        builder.append(getEndpoint());
        builder.append(", pathSegments = ");
        builder.append(getPathSegments());

        return builder.toString();
    }
}
