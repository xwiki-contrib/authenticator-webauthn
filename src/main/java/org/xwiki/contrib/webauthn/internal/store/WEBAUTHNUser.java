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

import java.util.Arrays;

import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;

/**
 * To manipulate WEBAUTHN metadata stored in a user profile.
 *
 * @version $Id$
 */
public class WEBAUTHNUser
{
    /**
     * The String reference of the class defining the object which contains the WEBAUTHN metadata in the user profile.
     */
    public static final String CLASS_FULLNAME = "XWiki.WEBAUTHN.UserClass";

    /**
     * The reference of the class defining the object which contains the WEBAUTHN metadata in the user profile.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "WEBAUTHN"), "UserClass");


    /**
     * The name of the property containing the WEBAUTHN credential id.
     */
    public static final String FIELD_ID = "id";

    // TODO: add different properties regarding WEBAUTHN
}
