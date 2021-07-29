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

import java.util.Collection;
import java.util.Optional;

import org.xwiki.contrib.webauthn.internal.data.CredentialRegistration;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.ByteArray;

/**
 * Implementation of CredentialRepository. An abstraction of the database lookups needed by the library.
 * <p>This is used by RelyingParty to look up credentials, usernames and user handles from
 * usernames, user handles and credential IDs, etc.
 *
 * @version $Id$
 */
public interface RegistrationStorage extends CredentialRepository
{
    /**
     * Add the registered webauthn credentials to the given XWiki username.
     */
    boolean addRegistrationByUsername(String username, CredentialRegistration reg);

    /**
     * Get all the registrations associated with the given XWiki username
     */
    Collection<CredentialRegistration> getRegistrationsByUsername(String username);

    /**
     * Get all the registrations associated with the given XWiki username and the credential Id
     */
    Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray credentialId);

    /**
     * Get all the registrations associated with the given userHandle
     */
    Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle);

    /**
     * Remove a registration associated with the given XWiki username
     */
    boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration);

    /**
     * Remove all registrations associated with the given XWiki username
     */
    boolean removeAllRegistrations(String username);

    /**
     * Update signature count after every successful authentication using webauthn credentials
     */
    void updateSignatureCount(AssertionResult result);

    /**
     * Check whether webauthn credentials exists for a given XWiki username or not
     */
    default boolean userExists(String username)
    {
        return !getRegistrationsByUsername(username).isEmpty();
    }
}
