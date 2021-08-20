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
/*
    package org.xwiki.contrib.webauthn.internal;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.webauthn.internal.data.AssertionRequestWrapper;
import org.xwiki.contrib.webauthn.internal.data.AssertionResponse;
import org.xwiki.contrib.webauthn.internal.data.CredentialRegistration;
import org.xwiki.contrib.webauthn.internal.util.Either;
import org.xwiki.contrib.webauthn.internal.util.SessionManager;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.cache.Cache;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.exception.AssertionFailedException;

import lombok.AllArgsConstructor;
import lombok.Value;
*/

/**
 * Main utility for authentication of a standard XWiki user using WebAuthn credentials
 *
 * @version $Id$
 */
 /*
@Component(roles = WebAuthnAuthenticator.class)
@Singleton
public class WebAuthnAuthenticator
{
    @Inject
    private Logger logger;

    private final Cache<ByteArray, AssertionRequestWrapper> assertRequestStorage;

    private final RegistrationStorage userStorage;

    private static final SecureRandom random = new SecureRandom();

    private final RelyingParty rp;

    private final ObjectMapper jsonMapper = JacksonCodecs.json();

    private final SessionManager sessions;

    public WebAuthnAuthenticator(Cache<ByteArray, AssertionRequestWrapper> assertRequestStorage,
        RegistrationStorage userStorage, RelyingParty rp,
        SessionManager sessions)
    {
        this.assertRequestStorage = assertRequestStorage;
        this.userStorage = userStorage;
        this.rp = rp;
        this.sessions = sessions;
    }

    private static ByteArray generateRandom(int length)
    {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    public Either<List<String>, AssertionRequestWrapper> startAuthentication(Optional<String> username)
    {
        logger.trace("startAuthentication username: {}", username);

        if (username.isPresent() && !userStorage.userExists(username.get())) {
            return Either.left(
                Collections.singletonList("The username \"" + username.get() + "\" is not registered."));
        } else {
            AssertionRequestWrapper request =
                new AssertionRequestWrapper(
                    generateRandom(32),
                    rp.startAssertion(StartAssertionOptions.builder().username(username).build()));

            assertRequestStorage.put(request.getRequestId(), request);

            return Either.right(request);
        }
    }

    @Value
    @AllArgsConstructor
    public static class SuccessfulAuthenticationResult
    {
        boolean success = true;
        AssertionRequestWrapper request;
        AssertionResponse response;
        Collection<CredentialRegistration> registrations;

        @JsonSerialize(using = AuthDataSerializer.class)
        AuthenticatorData authData;

        String username;
        ByteArray sessionToken;
        List<String> warnings;

        public SuccessfulAuthenticationResult(
            AssertionRequestWrapper request,
            AssertionResponse response,
            Collection<CredentialRegistration> registrations,
            String username,
            ByteArray sessionToken,
            List<String> warnings) {
            this(
                request,
                response,
                registrations,
                response.getCredential().getResponse().getParsedAuthenticatorData(),
                username,
                sessionToken,
                warnings);
        }
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String responseJson)
    {
        logger.trace("finishAuthentication responseJson: {}", responseJson);

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            logger.debug("Failed to decode response object", e);
            return Either.left(
                Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
        }

        AssertionRequestWrapper request = assertRequestStorage.getIfPresent(response.getRequestId());
        assertRequestStorage.invalidate(response.getRequestId());

        if (request == null) {
            return Either.left(Arrays.asList("Assertion failed!", "No such assertion in progress."));
        } else {
            try {
                AssertionResult result =
                    rp.finishAssertion(
                        FinishAssertionOptions.builder()
                            .request(request.getRequest())
                            .response(response.getCredential())
                            .build());

                if (result.isSuccess()) {
                    try {
                        userStorage.updateSignatureCount(result);
                    } catch (Exception e) {
                        logger.error(
                            "Failed to update signature count for user \"{}\", credential \"{}\"",
                            result.getUsername(),
                            response.getCredential().getId(),
                            e);
                    }

                    return Either.right(
                        new SuccessfulAuthenticationResult(
                            request,
                            response,
                            userStorage.getRegistrationsByUsername(result.getUsername()),
                            result.getUsername(),
                            sessions.createSession(result.getUserHandle()),
                            result.getWarnings()));
                } else {
                    return Either.left(Collections.singletonList("Assertion failed: Invalid assertion."));
                }
            } catch (AssertionFailedException e) {
                logger.debug("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed!", e.getMessage()));
            } catch (Exception e) {
                logger.error("Assertion failed", e);
                return Either.left(
                    Arrays.asList("Assertion failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }

    private static class AuthDataSerializer extends JsonSerializer<AuthenticatorData>
    {
        @Override
        public void serialize(AuthenticatorData value, JsonGenerator gen, SerializerProvider serializers)
            throws IOException
        {
            gen.writeStartObject();
            gen.writeStringField("rpIdHash", value.getRpIdHash().getHex());
            gen.writeObjectField("flags", value.getFlags());
            gen.writeNumberField("signatureCounter", value.getSignatureCounter());
            value
                .getAttestedCredentialData()
                .ifPresent(
                    acd -> {
                        try {
                            gen.writeObjectFieldStart("attestedCredentialData");
                            gen.writeStringField("aaguid", acd.getAaguid().getHex());
                            gen.writeStringField("credentialId", acd.getCredentialId().getHex());
                            gen.writeStringField("publicKey", acd.getCredentialPublicKey().getHex());
                            gen.writeEndObject();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
            gen.writeObjectField("extensions", value.getExtensions());
            gen.writeEndObject();
        }
    }
}
*/