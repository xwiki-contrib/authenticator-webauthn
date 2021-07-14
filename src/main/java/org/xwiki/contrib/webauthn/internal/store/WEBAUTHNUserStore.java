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
package org.xwiki.contrib.webauthn.internal.store;

import org.xwiki.component.annotation.Role;
import org.xwiki.query.QueryException;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Helper to manager WebAuthn profiles XClass and XObject.
 *
 * @version $Id$
 */
@Role
public interface WebAuthnUserStore
{
    /**
     * Add or update WebAuthn metadata in the user profile
     *
     * @param userDocument the document in which the WebAuthn user is stored
     * @param id the id associated with the WebAuthn credentials
     * TODO: Add more properties here definitely
     **/
    boolean updateWebAuthnUser(XWikiDocument userDocument, String id);

    /**
     * Search in the existing XWiki user if one already has WebAuthn credentials associated with them
     *
     * @param id the id associated with the WebAuthn credentials
     * TODO: Add more properties here definitely
     * @return the document of the user profile which already contains theses WebAuthn credentials
     * @throws XWikiException when failing the get the document
     * @throws QueryException when failing to search for the document
     */
    XWikiDocument searchDocument(String id) throws XWikiException, QueryException;
}
