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

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import javax.inject.Singleton;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.webauthn.internal.attestation.resolver.SimpleTrustResolverWithEquality;
import org.xwiki.contrib.webauthn.internal.data.AssertionRequestWrapper;
import org.xwiki.contrib.webauthn.internal.data.AssertionResponse;
import org.xwiki.contrib.webauthn.internal.data.CredentialRegistration;
import org.xwiki.contrib.webauthn.internal.data.RegistrationRequest;
import org.xwiki.contrib.webauthn.internal.data.RegistrationResponse;
import org.xwiki.contrib.webauthn.internal.data.U2fRegistrationResponse;
import org.xwiki.contrib.webauthn.internal.data.U2fRegistrationResult;
import org.xwiki.contrib.webauthn.internal.util.Either;
import org.xwiki.contrib.webauthn.internal.util.U2fVerifier;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.io.Closeables;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.AttestationResolver;
import com.yubico.webauthn.attestation.MetadataObject;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.attestation.StandardMetadataService;
import com.yubico.webauthn.attestation.TrustResolver;
import com.yubico.webauthn.attestation.resolver.CompositeAttestationResolver;
import com.yubico.webauthn.attestation.resolver.CompositeTrustResolver;
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;

import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.Value;

/**
 * Main utility for WebAuthn Server
 *
 * @version $Id$
 */
@Path("/webauthn")
@Produces(MediaType.APPLICATION_JSON)
@Component(roles = WebAuthnServerManager.class)
@Singleton
public class WebAuthnServerManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(WebAuthnServerManager.class);

    private static final SecureRandom random = new SecureRandom();

    private static final String PREVIEW_METADATA_PATH = "/preview-metadata.json";

    private final Cache<ByteArray, AssertionRequestWrapper> assertRequestStorage;

    private final Cache<ByteArray, RegistrationRequest> registerRequestStorage;

    private final RegistrationStorage userStorage;

    private final WebAuthnSessionManager sessions = new WebAuthnSessionManager();

    private final TrustResolver trustResolver =
        new CompositeTrustResolver(Arrays.asList(
                StandardMetadataService.createDefaultTrustResolver(), createExtraTrustResolver()));

    private final MetadataService metadataService =
        new StandardMetadataService(
            new CompositeAttestationResolver(
                Arrays.asList(
                    StandardMetadataService.createDefaultAttestationResolver(trustResolver),
                    createExtraMetadataResolver(trustResolver))));

    private final Clock clock = Clock.systemDefaultZone();

    private final ObjectMapper jsonMapper = JacksonCodecs.json();

    private final RelyingParty rp;

    public WebAuthnServerManager() throws InvalidAppIdException, CertificateException
    {
        this(
            new InMemoryRegistrationStorage(),
            newCache(),
            newCache(),
            WebAuthnConfiguration.getRpIdentity(),
            WebAuthnConfiguration.getOrigins(),
            WebAuthnConfiguration.getAppId());
    }

    public WebAuthnServerManager(
        RegistrationStorage userStorage,
        Cache<ByteArray, RegistrationRequest> registerRequestStorage,
        Cache<ByteArray, AssertionRequestWrapper> assertRequestStorage,
        RelyingPartyIdentity rpIdentity,
        Set<String> origins,
        Optional<AppId> appId)
        throws InvalidAppIdException, CertificateException
    {
        this.userStorage = userStorage;
        this.registerRequestStorage = registerRequestStorage;
        this.assertRequestStorage = assertRequestStorage;

        rp =
            RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(this.userStorage)
                .origins(origins)
                .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
                .metadataService(Optional.of(metadataService))
                .allowOriginPort(false)
                .allowOriginSubdomain(false)
                .allowUnrequestedExtensions(true)
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(true)
                .appId(appId)
                .build();
    }

    private static ByteArray generateRandom(int length)
    {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    private static MetadataObject readPreviewMetadata()
    {
        InputStream is = WebAuthnServerManager.class.getResourceAsStream(PREVIEW_METADATA_PATH);
        try {
            return JacksonCodecs.json().readValue(is, MetadataObject.class);
        } catch (IOException e) {
            throw ExceptionUtil.wrapAndLog(
                LOGGER, "Failed to read metadata from " + PREVIEW_METADATA_PATH, e);
        } finally {
            Closeables.closeQuietly(is);
        }
    }

    /**
     * Create a {@link TrustResolver} that accepts attestation certificates that are directly
     * recognised as trust anchors.
     */
    private static TrustResolver createExtraTrustResolver()
    {
        try {
            MetadataObject metadata = readPreviewMetadata();
            return new SimpleTrustResolverWithEquality(metadata.getParsedTrustedCertificates());
        } catch (CertificateException e) {
            throw ExceptionUtil.wrapAndLog(LOGGER, "Failed to read trusted certificate(s)", e);
        }
    }

    /**
     * Create a {@link AttestationResolver} with additional metadata for unreleased YubiKey Preview
     * devices.
     */
    private static AttestationResolver createExtraMetadataResolver(TrustResolver trustResolver)
    {
        try {
            MetadataObject metadata = readPreviewMetadata();
            return new SimpleAttestationResolver(Collections.singleton(metadata), trustResolver);
        } catch (CertificateException e) {
            throw ExceptionUtil.wrapAndLog(LOGGER, "Failed to read trusted certificate(s)", e);
        }
    }

    private static <K, V> Cache<K, V> newCache()
    {
        return CacheBuilder.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();
    }

    public Either<String, RegistrationRequest> startRegistration(
        @NonNull String username,
        Optional<String> displayName,
        boolean requireResidentKey,
        Optional<ByteArray> sessionToken)
        throws ExecutionException
    {
        LOGGER.trace("startRegistration username: {}", username);

        final Collection<CredentialRegistration> registrations = userStorage.getRegistrationsByUsername(username);
        final Optional<UserIdentity> existingUser =
            registrations.stream().findAny().map(CredentialRegistration::getUserIdentity);
        final boolean permissionGranted =
            existingUser
                .map(userIdentity -> sessions.isSessionForUser(userIdentity.getId(), sessionToken))
                .orElse(true);

        if (permissionGranted) {
            final UserIdentity registrationUserId =
                existingUser.orElseGet(
                    () ->
                        UserIdentity.builder()
                            .name(username)
                            .displayName(displayName.get())
                            .id(generateRandom(32))
                            .build());

            RegistrationRequest request =
                new RegistrationRequest(
                    username,
                    generateRandom(32),
                    rp.startRegistration(
                        StartRegistrationOptions.builder()
                            .user(registrationUserId)
                            .authenticatorSelection(
                                AuthenticatorSelectionCriteria.builder()
                                    .requireResidentKey(requireResidentKey)
                                    .build())
                            .build()),
                    Optional.of(sessions.createSession(registrationUserId.getId())));

            registerRequestStorage.put(request.getRequestId(), request);

            return Either.right(request);
        } else {
            return Either.left("The username \"" + username + "\" is already registered.");
        }
    }

    @Value
    public static class SuccessfulRegistrationResult
    {
        boolean success = true;
        RegistrationRequest request;
        RegistrationResponse response;
        CredentialRegistration registration;
        boolean attestationTrusted;
        Optional<AttestationCertInfo> attestationCert;

        @JsonSerialize(using = AuthDataSerializer.class)
        AuthenticatorData authData;

        String username;
        ByteArray sessionToken;

        public SuccessfulRegistrationResult(RegistrationRequest request, RegistrationResponse response,
            CredentialRegistration registration, boolean attestationTrusted, ByteArray sessionToken)
        {
            this.request = request;
            this.response = response;
            this.registration = registration;
            this.attestationTrusted = attestationTrusted;
            attestationCert =
                Optional.ofNullable(
                        response
                            .getCredential()
                            .getResponse()
                            .getAttestation()
                            .getAttestationStatement()
                            .get("x5c"))
                    .map(certs -> certs.get(0))
                    .flatMap(
                        (JsonNode certDer) -> {
                            try {
                                return Optional.of(new ByteArray(certDer.binaryValue()));
                            } catch (IOException e) {
                                LOGGER.error("Failed to get binary value from x5c element: {}", certDer, e);
                                return Optional.empty();
                            }
                        })
                    .map(AttestationCertInfo::new);

            this.authData = response.getCredential().getResponse().getParsedAuthenticatorData();
            this.username = request.getUsername();
            this.sessionToken = sessionToken;
        }
    }

    @Value
    public class SuccessfulU2fRegistrationResult
    {
        boolean success = true;
        RegistrationRequest request;
        U2fRegistrationResponse response;
        CredentialRegistration registration;
        boolean attestationTrusted;
        Optional<AttestationCertInfo> attestationCert;
        String username;
        ByteArray sessionToken;
    }

    @Value
    public static class AttestationCertInfo
    {
        ByteArray der;
        String text;

        public AttestationCertInfo(ByteArray certDer)
        {
            der = certDer;
            X509Certificate cert = null;
            try {
                cert = CertificateParser.parseDer(certDer.getBytes());
            } catch (CertificateException e) {
                LOGGER.error("Failed to parse attestation certificate");
            }
            if (cert == null) {
                text = null;
            } else {
                text = cert.toString();
            }
        }
    }

    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson)
    {
        LOGGER.trace("finishRegistration responseJson: {}", responseJson);
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            LOGGER.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            return Either.left(
                Arrays.asList(
                    "Registration failed!", "Failed to decode response object.", e.getMessage()));
        }

        RegistrationRequest request = registerRequestStorage.getIfPresent(response.getRequestId());
        registerRequestStorage.invalidate(response.getRequestId());

        if (request == null) {
            LOGGER.debug("fail finishRegistration responseJson: {}", responseJson);
            return Either.left(
                Arrays.asList("Registration failed!", "No such registration in progress."));
        } else {
            try {
                RegistrationResult registration =
                    rp.finishRegistration(
                        FinishRegistrationOptions.builder()
                            .request(request.getPublicKeyCredentialCreationOptions())
                            .response(response.getCredential())
                            .build());

                if (userStorage.userExists(request.getUsername())) {
                    boolean permissionGranted = false;

                    final boolean isValidSession =
                        request
                            .getSessionToken()
                            .map(
                                token ->
                                    sessions.isSessionForUser(
                                        request.getPublicKeyCredentialCreationOptions().getUser().getId(),
                                        token))
                            .orElse(false);

                    LOGGER.debug("Session token: {}", request.getSessionToken());
                    LOGGER.debug("Valid session: {}", isValidSession);

                    if (isValidSession) {
                        permissionGranted = true;
                        LOGGER.info("Session token accepted for user {}",
                            request.getPublicKeyCredentialCreationOptions().getUser().getId());
                    }

                    LOGGER.debug("permissionGranted: {}", permissionGranted);

                    if (!permissionGranted) {
                        throw new RegistrationFailedException(
                            new IllegalArgumentException(
                                String.format("User %s already exists", request.getUsername())));
                    }
                }

                return Either.right(
                    new SuccessfulRegistrationResult(
                        request,
                        response,
                        addRegistration(
                            request.getPublicKeyCredentialCreationOptions().getUser(),
                            response,
                            registration),
                        registration.isAttestationTrusted(),
                        sessions.createSession(
                            request.getPublicKeyCredentialCreationOptions().getUser().getId())));
            } catch (RegistrationFailedException e) {
                LOGGER.debug("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(Arrays.asList("Registration failed!", e.getMessage()));
            } catch (Exception e) {
                LOGGER.error("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(
                    Arrays.asList(
                        "Registration failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }

    public Either<List<String>, SuccessfulU2fRegistrationResult> finishU2fRegistration(
        String responseJson) throws ExecutionException
    {
        LOGGER.trace("finishU2fRegistration responseJson: {}", responseJson);
        U2fRegistrationResponse response = null;

        try {
            response = jsonMapper.readValue(responseJson, U2fRegistrationResponse.class);
        } catch (IOException e) {
            LOGGER.error("JSON error in finishU2fRegistration; responseJson: {}", responseJson, e);
            return Either.left(
                Arrays.asList(
                    "Registration failed!", "Failed to decode response object.", e.getMessage()));
        }

        RegistrationRequest request = registerRequestStorage.getIfPresent(response.getRequestId());
        registerRequestStorage.invalidate(response.getRequestId());

        if (request == null) {
            LOGGER.debug("fail finishU2fRegistration responseJson: {}", responseJson);
            return Either.left(
                Arrays.asList("Registration failed!", "No such registration in progress."));
        } else {

            try {
                ExceptionUtil.assure(
                    U2fVerifier.verify(rp.getAppId().get(), request, response),
                    "Failed to verify signature.");
            } catch (Exception e) {
                LOGGER.debug("Failed to verify U2F signature.", e);
                return Either.left(Arrays.asList("Failed to verify signature.", e.getMessage()));
            }

            X509Certificate attestationCert = null;

            try {
                attestationCert =
                    CertificateParser.parseDer(
                        response
                            .getCredential()
                            .getU2fResponse()
                            .getAttestationCertAndSignature()
                            .getBytes());
            } catch (CertificateException e) {
                LOGGER.error(
                    "Failed to parse attestation certificate: {}",
                    response.getCredential().getU2fResponse().getAttestationCertAndSignature(),
                    e);
            }

            Optional<Attestation> attestation = Optional.empty();

            try {
                if (attestationCert != null) {
                    attestation = Optional.of(
                        metadataService.getAttestation(Collections.singletonList(attestationCert)));
                }
            } catch (CertificateEncodingException e) {
                LOGGER.error("Failed to resolve attestation", e);
            }

            final U2fRegistrationResult result =
                U2fRegistrationResult.builder()
                    .keyId(
                        PublicKeyCredentialDescriptor.builder()
                            .id(response.getCredential().getU2fResponse().getKeyHandle())
                            .build())
                    .attestationTrusted(attestation.map(Attestation::isTrusted).orElse(false))
                    .publicKeyCose(
                        rawEcdaKeyToCose(response.getCredential().getU2fResponse().getPublicKey()))
                    .attestationMetadata(attestation)
                    .build();

            return Either.right(
                new SuccessfulU2fRegistrationResult(
                    request,
                    response,
                    addRegistration(
                        request.getPublicKeyCredentialCreationOptions().getUser(),
                        0,
                        result),
                    result.isAttestationTrusted(),
                    Optional.of(
                        new AttestationCertInfo(
                            response.getCredential().getU2fResponse().getAttestationCertAndSignature())),
                    request.getUsername(),
                    sessions.createSession(
                        request.getPublicKeyCredentialCreationOptions().getUser().getId())));
        }
    }

    public Either<List<String>, AssertionRequestWrapper> startAuthentication(Optional<String> username)
    {
        LOGGER.trace("startAuthentication username: {}", username);

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
            AssertionRequestWrapper request, AssertionResponse response,
            Collection<CredentialRegistration> registrations, String username,
            ByteArray sessionToken, List<String> warnings)
        {
            this(
                request, response,
                registrations, response.getCredential().getResponse().getParsedAuthenticatorData(),
                username, sessionToken, warnings);
        }
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String responseJson)
    {
        LOGGER.trace("finishAuthentication responseJson: {}", responseJson);

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            LOGGER.debug("Failed to decode response object", e);
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
                        LOGGER.error(
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
                LOGGER.debug("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed!", e.getMessage()));
            } catch (Exception e) {
                LOGGER.error("Assertion failed", e);
                return Either.left(
                    Arrays.asList("Assertion failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }

    @Value
    public static class DeregisterCredentialResult
    {
        boolean success = true;
        CredentialRegistration droppedRegistration;
        boolean accountDeleted;
    }

    public Either<List<String>, DeregisterCredentialResult> deregisterCredential(
        @NonNull ByteArray sessionToken, ByteArray credentialId)
    {
        LOGGER.trace("deregisterCredential session: {}, credentialId: {}", sessionToken, credentialId);

        if (credentialId == null || credentialId.getBytes().length == 0) {
            return Either.left(Collections.singletonList("Credential ID must not be empty."));
        }

        Optional<ByteArray> session = sessions.getSession(sessionToken);

        if (session.isPresent()) {
            ByteArray userHandle = session.get();
            Optional<String> username = userStorage.getUsernameForUserHandle(userHandle);

            if (username.isPresent()) {
                Optional<CredentialRegistration> credReg =
                    userStorage.getRegistrationByUsernameAndCredentialId(username.get(), credentialId);

                if (credReg.isPresent()) {
                    userStorage.removeRegistrationByUsername(username.get(), credReg.get());

                    return Either.right(
                        new DeregisterCredentialResult(
                            credReg.get(), !userStorage.userExists(username.get())));
                } else {
                    return Either.left(
                        Collections.singletonList("Credential ID not registered:" + credentialId));
                }
            } else {
                return Either.left(Collections.singletonList("Invalid user handle"));
            }
        } else {
            return Either.left(Collections.singletonList("Invalid session"));
        }
    }

    public <T> Either<List<String>, T> deleteAccount(String username, Supplier<T> onSuccess)
    {
        LOGGER.trace("deleteAccount username: {}", username);

        if (username == null || username.isEmpty()) {
            return Either.left(Collections.singletonList("Username must not be empty."));
        }

        boolean removed = userStorage.removeAllRegistrations(username);

        if (removed) {
            return Either.right(onSuccess.get());
        } else {
            return Either.left(Collections.singletonList("Username not registered:" + username));
        }
    }

    private CredentialRegistration addRegistration(UserIdentity userIdentity, RegistrationResponse response,
        RegistrationResult result)
    {
        return addRegistration(
            userIdentity,
            response
                .getCredential()
                .getResponse()
                .getAttestation()
                .getAuthenticatorData()
                .getSignatureCounter(),
            RegisteredCredential.builder()
                .credentialId(result.getKeyId().getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(result.getPublicKeyCose())
                .signatureCount(
                    response
                        .getCredential()
                        .getResponse()
                        .getParsedAuthenticatorData()
                        .getSignatureCounter())
                .build(),
            result.getAttestationMetadata());
    }

    private CredentialRegistration addRegistration(UserIdentity userIdentity,
        long signatureCount, U2fRegistrationResult result)
    {
        return addRegistration(
            userIdentity,
            signatureCount,
            RegisteredCredential.builder()
                .credentialId(result.getKeyId().getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(result.getPublicKeyCose())
                .signatureCount(signatureCount)
                .build(),
            result.getAttestationMetadata());
    }

    private CredentialRegistration addRegistration(UserIdentity userIdentity, long signatureCount,
        RegisteredCredential credential, Optional<Attestation> attestationMetadata)
    {
        CredentialRegistration reg =
            CredentialRegistration.builder()
                .userIdentity(userIdentity)
                .registrationTime(clock.instant())
                .credential(credential)
                .signatureCount(signatureCount)
                .attestationMetadata(attestationMetadata)
                .build();

        LOGGER.debug("Adding registration: user: {}, credential: {}", userIdentity, credential);
        userStorage.addRegistrationByUsername(userIdentity.getName(), reg);
        return reg;
    }

    static ByteArray rawEcdaKeyToCose(ByteArray key)
    {
        final byte[] keyBytes = key.getBytes();

        if (!(keyBytes.length == 64 || (keyBytes.length == 65 && keyBytes[0] == 0x04))) {
            throw new IllegalArgumentException(
                String.format("Raw key must be 64 bytes long or be 65 bytes long and start with 0x04, "
                        + "was %d bytes starting with %02x", keyBytes.length, keyBytes[0]));
        }

        final int start = keyBytes.length == 64 ? 0 : 1;

        Map<Long, Object> coseKey = new HashMap<>();

        // Key type: EC
        coseKey.put(1L, 2L);
        coseKey.put(3L, COSEAlgorithmIdentifier.ES256.getId());
        // Curve: P-256
        coseKey.put(-1L, 1L);
        // x
        coseKey.put(-2L, Arrays.copyOfRange(keyBytes, start, start + 32));
        // y
        coseKey.put(-3L, Arrays.copyOfRange(keyBytes, start + 32, start + 64));

        return new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes());
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
