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
package org.xwiki.contrib.webauthn.internal.util;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.data.ByteArray;

import lombok.NonNull;

/**
 * Helper to manage user sessions
 */
public class SessionManager
{
    private final SecureRandom random = new SecureRandom();

    private final Cache<ByteArray, ByteArray> sessionIdsToUsers = newCache();
    private final Cache<ByteArray, ByteArray> usersToSessionIds = newCache();

    private static <K, V> Cache<K, V> newCache()
    {
        return CacheBuilder.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(5, TimeUnit.MINUTES)
            .build();
    }

    /**
     * @return Create a new session for the given user, or return the existing one.
     **/
    public ByteArray createSession(@NonNull ByteArray userHandle) throws ExecutionException
    {
        ByteArray sessionId = usersToSessionIds.get(userHandle, () -> generateRandom(32));
        sessionIdsToUsers.put(sessionId, userHandle);
        return sessionId;
    }

    /**
     * @return the user handle of the given session, if any.
     **/
    public Optional<ByteArray> getSession(@NonNull ByteArray token)
    {
        return Optional.ofNullable(sessionIdsToUsers.getIfPresent(token));
    }

    public boolean isSessionForUser(@NonNull ByteArray claimedUserHandle, @NonNull ByteArray token)
    {
        return getSession(token).map(claimedUserHandle::equals).orElse(false);
    }

    public boolean isSessionForUser(@NonNull ByteArray claimedUserHandle, @NonNull Optional<ByteArray> token)
    {
        return token.map(t -> isSessionForUser(claimedUserHandle, t)).orElse(false);
    }

    public ByteArray generateRandom(int length)
    {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

}
