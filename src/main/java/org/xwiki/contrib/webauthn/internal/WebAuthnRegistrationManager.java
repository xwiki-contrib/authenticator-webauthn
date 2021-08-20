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
import java.net.MalformedURLException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;

import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.webauthn.internal.data.CredentialRegistration;
import org.xwiki.contrib.webauthn.internal.data.RegistrationRequest;
import org.xwiki.contrib.webauthn.internal.data.RegistrationResponse;
import org.xwiki.contrib.webauthn.internal.event.WebAuthnUserEventData;
import org.xwiki.contrib.webauthn.internal.event.WebAuthnUserUpdating;
import org.xwiki.contrib.webauthn.internal.store.WebAuthnUserStore;
import org.xwiki.contrib.webauthn.internal.util.ContentResponse;
import org.xwiki.contrib.webauthn.internal.util.Either;
import org.xwiki.contrib.webauthn.internal.util.SessionManager;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.QueryException;
import org.xwiki.template.TemplateManager;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.google.common.cache.Cache;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.web.XWikiRequest;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.exception.RegistrationFailedException;

import lombok.NonNull;
import lombok.Value;
import lombok.val;
*/

/**
 * Main utility for registration of WebAuthn credentials for a standard XWiki user
 *
 * @version $Id$
 */

/*
@Component(roles = WebAuthnRegistrationManager.class)
@Singleton
public class WebAuthnRegistrationManager
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private WebAuthnUserStore store;

    @Inject
    private ObservationManager observation;

    @Inject
    private WebAuthnConfiguration configuration;

    @Inject
    private static Logger logger;

    @Inject
    private RegistrationStorage userStorage;

    @Inject
    private TemplateManager templates;

    private final ObjectMapper jsonMapper = JacksonCodecs.json();

    private final SessionManager sessions;


    private final Clock clock = Clock.systemDefaultZone();

    private static final SecureRandom random = new SecureRandom();

    private final Cache<ByteArray, RegistrationRequest> registerRequestStorage;

    public WebAuthnRegistrationManager(SessionManager sessions,
        Cache<ByteArray, RegistrationRequest> registerRequestStorage)
    {
        this.sessions = sessions;
        this.registerRequestStorage = registerRequestStorage;
    }

    /**
     * The RP identity, here it means the XWiki instance
     */
/*
    RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
        .id("example.com")
        .name("XWiki WebAuthn")
        .build();

    RelyingParty rp = RelyingParty.builder()
        .identity(rpIdentity)
        .credentialRepository(new RegistrationStorage())
        .build();


    private static ByteArray generateRandom(int length)
    {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    public Either<String, RegistrationRequest> startRegistration(@NonNull String username, Optional<String> displayName,
        Optional<String> credentialNickname, boolean requireResidentKey, Optional<ByteArray> sessionToken)
        throws ExecutionException
    {
        logger.trace(
            "startRegistration username: {}, credentialNickname: {}", username, credentialNickname);

        final Collection<CredentialRegistration> registrations = this.userStorage.getRegistrationsByUsername(username);

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
                    credentialNickname,
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

    private final class StartRegistrationResponse
    {
        public final boolean success = true;
        public final RegistrationRequest request;

        private StartRegistrationResponse(RegistrationRequest request) throws MalformedURLException
        {
            this.request = request;
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
                                logger.error("Failed to get binary value from x5c element: {}", certDer, e);
                                return Optional.empty();
                            }
                        })
                    .map(AttestationCertInfo::new);

            this.authData = response.getCredential().getResponse().getParsedAuthenticatorData();
            this.username = request.getUsername();
            this.sessionToken = sessionToken;
        }
    }


    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson)
    {
        logger.trace("finishRegistration responseJson: {}", responseJson);
        RegistrationResponse response = null;

        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            return Either.left(
                Arrays.asList("Registration failed!", "Failed to decode response object.", e.getMessage()));
        }

        RegistrationRequest request = registerRequestStorage.getIfPresent(response.getRequestId());
        registerRequestStorage.invalidate(response.getRequestId());

        if (request == null) {
            logger.debug("fail finishRegistration responseJson: {}", responseJson);
            return Either.left(
                Arrays.asList("Registration failed!", "No such registration in progress."));
        } else {
            try {
                com.yubico.webauthn.RegistrationResult registration =
                    rp.finishRegistration(
                        FinishRegistrationOptions.builder()
                            .request(request.getPublicKeyCredentialCreationOptions())
                            .response(response.getCredential())
                            .build());

                if (this.userStorage.userExists(request.getUsername())) {
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

                    logger.debug("Session token: {}", request.getSessionToken());
                    logger.debug("Valid session: {}", isValidSession);

                    if (isValidSession) {
                        permissionGranted = true;
                        logger.info(
                            "Session token accepted for user {}",
                            request.getPublicKeyCredentialCreationOptions().getUser().getId());
                    }

                    logger.debug("permissionGranted: {}", permissionGranted);

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
                            request.getCredentialNickname(),
                            response,
                            registration),
                        registration.isAttestationTrusted(),
                        sessions.createSession(
                            request.getPublicKeyCredentialCreationOptions().getUser().getId())));
            } catch (RegistrationFailedException e) {
                logger.debug("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(Arrays.asList("Registration failed!", e.getMessage()));
            } catch (Exception e) {
                logger.error("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(
                    Arrays.asList("Registration failed unexpectedly; this is likely a bug.", e.getMessage()));
            }
        }
    }


    private CredentialRegistration addRegistration(UserIdentity userIdentity, Optional<String> nickname,
        RegistrationResponse response, RegistrationResult result)
    {
        return addRegistration(
            userIdentity,
            nickname,
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

    private CredentialRegistration addRegistration(UserIdentity userIdentity, Optional<String> nickname,
        long signatureCount, RegisteredCredential credential, Optional<Attestation> attestationMetadata)
    {
        CredentialRegistration reg =
            CredentialRegistration.builder()
                .userIdentity(userIdentity)
                .credentialNickname(nickname)
                .registrationTime(clock.instant())
                .credential(credential)
                .signatureCount(signatureCount)
                .attestationMetadata(attestationMetadata)
                .build();

        logger.debug("Adding registration: user: {}, nickname: {}, credential: {}",
            userIdentity,
            nickname,
            credential);
        this.userStorage.addRegistrationByUsername(userIdentity.getName(), reg);
        return reg;
    }

    public Principal updateUser(RegisteredCredential credential, UserIdentity userIdentity,
        ByteArray publicKeyCose, int signatureCount) throws QueryException, XWikiException
    {
        XWikiDocument userDocument =
            this.store.searchDocument(credential.getCredentialId().toString(),
            userIdentity.toString(),publicKeyCose.toString(), signatureCount);

        XWikiDocument modifiableDocument;
        boolean newUser;

        if (userDocument == null) {
            newUser = true;
            modifiableDocument = userDocument;
        } else {
            // Don't change the document author to not change document execution right
            newUser = false;
            modifiableDocument = userDocument.clone();
        }

        XWikiContext xcontext = this.xcontextProvider.get();

        // Set user fields
        BaseClass userClass = xcontext.getWiki().getUserClass(xcontext);
        BaseObject userObject = modifiableDocument.getXObject(userClass.getDocumentReference(), true, xcontext);

        // Make sure the user is active by default
        userObject.set("active", 1, xcontext);

        // Set WebAuthn fields
        this.store.updateWebAuthnUser(modifiableDocument, credential.getCredentialId().toString(),
            userIdentity.toString(),publicKeyCose.toString(), signatureCount);

        // Data to send with the event
        WebAuthnUserEventData eventData =
            new WebAuthnUserEventData(credential, userIdentity, publicKeyCose, signatureCount);

        // Notify
        this.observation.notify(new WebAuthnUserUpdating(modifiableDocument.getDocumentReference()), modifiableDocument,
            eventData);

        // Apply the modifications
        if (newUser || userDocument.apply(modifiableDocument)) {
            String comment = null;
            if (newUser) {
                comment = "Created user xobject from WebAuthn";
            }

            xcontext.getWiki().saveDocument(userDocument, comment, xcontext);
        }
        return new SimplePrincipal(userDocument.getPrefixedFullName());
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
                logger.error("Failed to parse attestation certificate");
            }
            if (cert == null) {
                text = null;
            } else {
                text = cert.toString();
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


    public void logout()
    {
        XWikiRequest request = this.xcontextProvider.get().getRequest();

        // Send logout request
        // this.sendLogout();

        // TODO: remove cookies

        // Make sure the session is free from anything related to a previously authenticated user (i.e. in case we are
        // just after a logout)
        request.getSession().removeAttribute(WebAuthnConfiguration.PROP_XWIKIUSER);
        request.getSession().removeAttribute(WebAuthnConfiguration.PROP_INITIAL_REQUEST);
        request.getSession().removeAttribute(WebAuthnConfiguration.PROP_SKIPPED);
        request.getSession().removeAttribute(WebAuthnConfiguration.PROP_STATE);
    }

    /**
     * Run a template and generate a HTML content response.
     *
     * @param templateName the name of the template
     * @return the HTML content response
     * @throws Exception when failing to execute the template
     */
/*
    public Response executeTemplate(String templateName) throws Exception
    {
        String html = this.templates.render(templateName);

        return new ContentResponse(ContentResponse.CONTENTTYPE_HTML, html, HTTPResponse.SC_OK);
    }

    public void executeTemplate(String templateName, HttpServletResponse servletResponse) throws Exception
    {
        Response response = executeTemplate(templateName);

        ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
    }
}
*/