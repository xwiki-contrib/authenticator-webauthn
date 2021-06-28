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
 * Implementation of CredentialRepository
 *
 * @version $Id$
 */
public interface RegistrationStorage extends CredentialRepository
{
    boolean addRegistrationByUsername(String username, CredentialRegistration reg);

    Collection<CredentialRegistration> getRegistrationsByUsername(String username);

    Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray credentialId);

    Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle);

    boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration);

    boolean removeAllRegistrations(String username);

    void updateSignatureCount(AssertionResult result);

    default boolean userExists(String username)
    {
        return !getRegistrationsByUsername(username).isEmpty();
    }
}
