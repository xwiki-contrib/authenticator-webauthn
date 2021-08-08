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
import java.util.HashSet;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.webauthn.internal.data.CredentialRegistration;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;


public class InMemoryRegistrationStorage implements RegistrationStorage, CredentialRepository
{
    /**
     * Build a cache which should be automatically removed once after 1 day has elapsed after
     * the it's creation, the most recent replacement of its value, or its last access.
     *
     * TODO: Change this ASAP
     */
    private final Cache<String, Set<CredentialRegistration>> storage =
        CacheBuilder.newBuilder().maximumSize(1000).expireAfterAccess(1, TimeUnit.DAYS).build();

    private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryRegistrationStorage.class);

    /**
     * Add webauthn credentials registration for a standard xwiki user
     *
     * @param username the standard xwiki username
     * @param reg properties associated with a WebAuthn credential
     * @return an error if credentials for the username already exists
     */
    @Override
    public boolean addRegistrationByUsername(String username, CredentialRegistration reg)
    {
        try {
            return storage.get(username, HashSet::new).add(reg);
        } catch (ExecutionException e) {
            LOGGER.error("Failed to add registration", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * @return credential IDs of all credentials registered to the given username.
     */
    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username)
    {
        return getRegistrationsByUsername(username).stream().map(registration ->
            PublicKeyCredentialDescriptor.builder()
                .id(registration.getCredential().getCredentialId())
                .build())
            .collect(Collectors.toSet());
    }

    /**
     * @return users for which we have generated webauthn credentials, error if none.
     */
    @Override
    public Collection<CredentialRegistration> getRegistrationsByUsername(String username)
    {
        try {
            return storage.get(username, HashSet::new);
        } catch (ExecutionException e) {
            LOGGER.error("Registration lookup failed", e);
            throw new RuntimeException(e);
        }
    }

    /**
     * @return  all registrations for the given userHandle.
     */
    @Override
    public Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle)
    {
        return storage.asMap().values().stream().flatMap(Collection::stream)
            .filter(credentialRegistration ->
                    userHandle.equals(credentialRegistration.getUserIdentity().getId()))
            .collect(Collectors.toList());
    }

    /**
     * @return username corresponding to the given user handle, inverse of
     * {@link #getUserHandleForUsername(String)}
     */
    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle)
    {
        return getRegistrationsByUserHandle(userHandle).stream()
            .findAny()
            .map(CredentialRegistration::getUsername);
    }

    /**
     * @return user handle corresponding to the given username, inverse of
     * {@link #getUsernameForUserHandle(ByteArray)}
     */
    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username)
    {
        return getRegistrationsByUsername(username).stream()
            .findAny()
            .map(reg -> reg.getUserIdentity().getId());
    }

    @Override
    public void updateSignatureCount(AssertionResult result)
    {
        CredentialRegistration registration =
            getRegistrationByUsernameAndCredentialId(result.getUsername(), result.getCredentialId())
                .orElseThrow(
                    () ->
                        new NoSuchElementException(String.format(
                            "Credential \"%s\" is not registered to user \"%s\"",
                                result.getCredentialId(), result.getUsername())));

        Set<CredentialRegistration> regs = storage.getIfPresent(result.getUsername());
        if (regs != null) {
            regs.remove(registration);
            regs.add(registration.withSignatureCount(result.getSignatureCount()));
        }
    }

    @Override
    public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray id)
    {
        try {
            return storage.get(username, HashSet::new).stream()
                .filter(credReg -> id.equals(credReg.getCredential().getCredentialId()))
                .findFirst();
        } catch (ExecutionException e) {
            LOGGER.error("Registration lookup failed", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration)
    {
        try {
            return storage.get(username, HashSet::new).remove(credentialRegistration);
        } catch (ExecutionException e) {
            LOGGER.error("Failed to remove registration", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean removeAllRegistrations(String username)
    {
        storage.invalidate(username);
        return true;
    }

    /**
     * Look up the public key and stored signature count for the given credential registered to the
     * given user.
     *
     * <p>The returned {@link RegisteredCredential} is not expected to be long-lived. It may be read
     * directly from a database or assembled from other components.
     */
    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle)
    {

        Optional<CredentialRegistration> registrationMaybe =
            storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(credReg -> credentialId.equals(credReg.getCredential().getCredentialId()))
                .findAny();

        LOGGER.debug(
            "Lookup credential ID: {}, user handle: {}, result: {}", credentialId, userHandle, registrationMaybe);

        return registrationMaybe.flatMap(
            registration -> Optional.of(
                RegisteredCredential.builder()
                    .credentialId(registration.getCredential().getCredentialId())
                    .userHandle(registration.getUserIdentity().getId())
                    .publicKeyCose(registration.getCredential().getPublicKeyCose())
                    .signatureCount(registration.getSignatureCount())
                    .build()));
    }

    /**
     * Look up all credentials with the given credential ID, regardless of what user they're
     * registered to.
     *
     * <p>This is used to refuse registration of duplicate credential IDs. Therefore, under normal
     * circumstances this method should only return zero or one credential (this is an expected
     * consequence, not an interface requirement).
     */
    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId)
    {
        return CollectionUtil.immutableSet(
            storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(reg -> reg.getCredential().getCredentialId().equals(credentialId))
                .map(reg -> RegisteredCredential.builder()
                    .credentialId(reg.getCredential().getCredentialId())
                    .userHandle(reg.getUserIdentity().getId())
                    .publicKeyCose(reg.getCredential().getPublicKeyCose())
                    .signatureCount(reg.getSignatureCount())
                    .build())
                .collect(Collectors.toSet()));
    }
}