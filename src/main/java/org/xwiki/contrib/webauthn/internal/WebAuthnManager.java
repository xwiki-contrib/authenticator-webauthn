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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.webauthn.internal.data.AssertionRequestWrapper;
import org.xwiki.contrib.webauthn.internal.data.RegistrationRequest;
import org.xwiki.contrib.webauthn.internal.util.Either;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xpn.xwiki.XWikiContext;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import com.yubico.webauthn.meta.VersionInfo;

import lombok.NonNull;

/**
 * Main utility for WebAuthn
 *
 * @version $Id$
 */
@Path("/xwiki")
@Produces(MediaType.APPLICATION_JSON)
@Component(roles = WebAuthnManager.class)
@Singleton
public class WebAuthnManager
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private WebAuthnConfiguration configuration;

    private static final Logger LOGGER = LoggerFactory.getLogger(WebAuthnManager.class);

    private final WebAuthnServerManager server;

    private final ObjectMapper jsonMapper = JacksonCodecs.json();

    private final JsonNodeFactory jsonFactory = JsonNodeFactory.instance;

    public WebAuthnManager() throws InvalidAppIdException, CertificateException
    {
        this(new WebAuthnServerManager());
    }

    public WebAuthnManager(WebAuthnServerManager server)
    {
        this.server = server;
    }

    @Context private UriInfo uriInfo;

    private final class IndexResponse
    {
        public final Index actions = new Index();
        public final Info info = new Info();

        private IndexResponse() throws MalformedURLException {}
    }

    private final class Index
    {
        public final URL authenticate;
        public final URL deleteAccount;
        public final URL deregister;
        public final URL register;

        public Index() throws MalformedURLException
        {
            authenticate = uriInfo.getAbsolutePathBuilder().path("authenticate").build().toURL();
            deleteAccount = uriInfo.getAbsolutePathBuilder().path("delete-account").build().toURL();
            deregister = uriInfo.getAbsolutePathBuilder().path("action").path("deregister").build().toURL();
            register = uriInfo.getAbsolutePathBuilder().path("register").build().toURL();
        }
    }

    private final class Info
    {
        public final URL version;

        public Info() throws MalformedURLException
        {
            version = uriInfo.getAbsolutePathBuilder().path("version").build().toURL();
        }
    }

    @GET
    public Response index() throws IOException
    {
        return Response.ok(writeJson(new IndexResponse())).build();
    }

    private static final class VersionResponse
    {
        public final VersionInfo version = VersionInfo.getInstance();
    }

    @GET
    @Path("version")
    public Response version() throws JsonProcessingException
    {
        return Response.ok(writeJson(new VersionResponse())).build();
    }

    private final class StartRegistrationResponse
    {
        public final boolean success = true;
        public final RegistrationRequest request;
        public final StartRegistrationActions actions = new StartRegistrationActions();

        private StartRegistrationResponse(RegistrationRequest request) throws MalformedURLException
        {
            this.request = request;
        }
    }

    private final class StartRegistrationActions
    {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        public final URL finishU2f = uriInfo.getAbsolutePathBuilder().path("finish-u2f").build().toURL();

        private StartRegistrationActions() throws MalformedURLException {}
    }

    @Consumes("application/x-www-form-urlencoded")
    @Path("register")
    @POST
    public Response startRegistration(
        @NonNull @FormParam("username") String username,
        @NonNull @FormParam("displayName") String displayName,
        @FormParam("requireResidentKey") @DefaultValue("false") boolean requireResidentKey,
        @FormParam("sessionToken") String sessionTokenBase64)
        throws MalformedURLException, ExecutionException
    {
        LOGGER.trace("startRegistration username: {}, displayName: {}, requireResidentKey: {}",
            username, displayName, requireResidentKey);

        Either<String, RegistrationRequest> result =
            server.startRegistration(username, Optional.of(displayName), requireResidentKey,
                Optional.ofNullable(sessionTokenBase64)
                    .map(base64 -> {
                        try {
                            return ByteArray.fromBase64Url(base64);
                        } catch (Base64UrlException e) {
                            throw new RuntimeException(e);
                        }
                    }));

        if (result.isRight()) {
            return startResponse("startRegistration", new StartRegistrationResponse(result.right().get()));
        } else {
            return messagesJson(Response.status(Response.Status.BAD_REQUEST), result.left().get());
        }
    }


    @Path("register/finish")
    @POST
    public Response finishRegistration(@NonNull String responseJson)
    {
        LOGGER.trace("finishRegistration responseJson: {}", responseJson);

        Either<List<String>, WebAuthnServerManager.SuccessfulRegistrationResult> result =
            server.finishRegistration(responseJson);

        return finishResponse(result,
            "Attestation verification failed; further error message(s) were unfortunately lost"
                + " to an internal server error.", "finishRegistration", responseJson);
    }

    @Path("register/finish-u2f")
    @POST
    public Response finishU2fRegistration(@NonNull String responseJson) throws ExecutionException
    {
        LOGGER.trace("finishRegistration responseJson: {}", responseJson);

        Either<List<String>, WebAuthnServerManager.SuccessfulU2fRegistrationResult> result =
            server.finishU2fRegistration(responseJson);

        return finishResponse(result,
            "U2F registration failed; further error message(s) were unfortunately lost"
                + " to an internal server error.", "finishU2fRegistration", responseJson);
    }

    private final class StartAuthenticationResponse
    {
        public final boolean success = true;
        public final AssertionRequestWrapper request;
        public final StartAuthenticationActions actions = new StartAuthenticationActions();

        private StartAuthenticationResponse(AssertionRequestWrapper request) throws MalformedURLException
        {
            this.request = request;
        }
    }

    private final class StartAuthenticationActions
    {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();

        private StartAuthenticationActions() throws MalformedURLException {}
    }

    @Consumes("application/x-www-form-urlencoded")
    @Path("authenticate")
    @POST
    public Response startAuthentication(@FormParam("username") String username) throws MalformedURLException
    {
        LOGGER.trace("startAuthentication username: {}", username);

        Either<List<String>, AssertionRequestWrapper> request =
            server.startAuthentication(Optional.ofNullable(username));

        if (request.isRight()) {
            return startResponse(
                "startAuthentication", new StartAuthenticationResponse(request.right().get()));
        } else {
            return messagesJson(Response.status(Response.Status.BAD_REQUEST), request.left().get());
        }
    }

    @Path("authenticate/finish")
    @POST
    public Response finishAuthentication(@NonNull String responseJson)
    {
        LOGGER.trace("finishAuthentication responseJson: {}", responseJson);

        Either<List<String>, WebAuthnServerManager.SuccessfulAuthenticationResult> result =
            server.finishAuthentication(responseJson);

        return finishResponse(result,
            "Authentication verification failed; further error message(s) were unfortunately lost"
                + " to an internal server error.", "finishAuthentication", responseJson);
    }

    @Path("action/deregister")
    @POST
    public Response deregisterCredential(
        @NonNull @FormParam("sessionToken") String sessionTokenBase64,
        @NonNull @FormParam("credentialId") String credentialIdBase64)
        throws MalformedURLException, Base64UrlException
    {
        LOGGER.trace("deregisterCredential sesion: {}, credentialId: {}", sessionTokenBase64, credentialIdBase64);

        final ByteArray credentialId;

        try {
            credentialId = ByteArray.fromBase64Url(credentialIdBase64);
        } catch (Base64UrlException e) {
            return messagesJson(
                Response.status(Response.Status.BAD_REQUEST),
                "Credential ID is not valid Base64Url data: " + credentialIdBase64);
        }

        Either<List<String>, WebAuthnServerManager.DeregisterCredentialResult> result =
            server.deregisterCredential(ByteArray.fromBase64Url(sessionTokenBase64), credentialId);

        if (result.isRight()) {
            return finishResponse(
                result, "Failed to deregister credential; further error message(s) were unfortunately lost"
                    + " to an internal server error.", "deregisterCredential", "");
        } else {
            return messagesJson(Response.status(Response.Status.BAD_REQUEST), result.left().get());
        }
    }

    @Path("delete-account")
    @DELETE
    public Response deleteAccount(@NonNull @FormParam("username") String username)
    {
        LOGGER.trace("deleteAccount username: {}", username);

        Either<List<String>, JsonNode> result =
            server.deleteAccount(
                username,
                () ->
                    ((ObjectNode) jsonFactory.objectNode().set("success", jsonFactory.booleanNode(true)))
                        .set("deletedAccount", jsonFactory.textNode(username)));

        if (result.isRight()) {
            return Response.ok(result.right().get().toString()).build();
        } else {
            return messagesJson(Response.status(Response.Status.BAD_REQUEST), result.left().get());
        }
    }

    private Response startResponse(String operationName, Object request)
    {
        try {
            String json = writeJson(request);
            LOGGER.debug("{} JSON response: {}", operationName, json);
            return Response.ok(json).build();
        } catch (IOException e) {
            LOGGER.error("Failed to encode response as JSON: {}", request, e);
            return jsonFail();
        }
    }

    private Response finishResponse(Either<List<String>, ?> result, String jsonFailMessage,
        String methodName, String responseJson)
    {
        if (result.isRight()) {
            try {
                return Response.ok(writeJson(result.right().get())).build();
            } catch (JsonProcessingException e) {
                LOGGER.error("Failed to encode response as JSON: {}", result.right().get(), e);
                return messagesJson(Response.ok(), jsonFailMessage);
            }
        } else {
            LOGGER.debug("fail {} responseJson: {}", methodName, responseJson);
            return messagesJson(Response.status(Response.Status.BAD_REQUEST), result.left().get());
        }
    }

    private Response jsonFail()
    {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
            .entity("{\"messages\":[\"Failed to encode response as JSON\"]}")
            .build();
    }

    private Response messagesJson(Response.ResponseBuilder response, String message)
    {
        return messagesJson(response, Arrays.asList(message));
    }

    private Response messagesJson(Response.ResponseBuilder response, List<String> messages)
    {
        LOGGER.debug("Encoding messages as JSON: {}", messages);

        try {
            return response
                .entity(writeJson(
                    jsonFactory
                        .objectNode()
                        .set("messages", jsonFactory
                            .arrayNode()
                            .addAll(messages.stream()
                                .map(jsonFactory::textNode)
                                .collect(Collectors.toList())))))
                .build();
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to encode messages as JSON: {}", messages, e);
            return jsonFail();
        }
    }

    private String writeJson(Object o) throws JsonProcessingException
    {
        if (uriInfo.getQueryParameters().keySet().contains("pretty")) {
            return jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(o);
        } else {
            return jsonMapper.writeValueAsString(o);
        }
    }

    /**
     * Generate and return an external {@link URI} for passed endpoint in the current instance.
     *
     * @param endpoint the endpoint
     * @return the {@link URI}
     * @throws MalformedURLException when failing to get server URL
     * @throws URISyntaxException when failing to create the URI
     */
    public URI createEndPointURI(String endpoint) throws MalformedURLException, URISyntaxException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        StringBuilder base = new StringBuilder();

        base.append(xcontext.getURLFactory().getServerURL(xcontext));

        if (base.charAt(base.length() - 1) != '/') {
            base.append('/');
        }

        String webAppPath = xcontext.getWiki().getWebAppPath(xcontext);
        if (!webAppPath.equals("/")) {
            base.append(webAppPath);
        }

        base.append("webauthn/");

        return createEndPointURI(base.toString(), endpoint);
    }

    /**
     * Generate and return an external {@link URI} for passed endpoint in the passed instance.
     *
     * @param base target instance
     * @param endpoint the endpoint
     * @return the {@link URI}
     * @throws URISyntaxException when failing to create the URI
     */
    public URI createEndPointURI(String base, String endpoint) throws URISyntaxException
    {
        StringBuilder uri = new StringBuilder(base);

        if (!base.endsWith("/")) {
            uri.append('/');
        }

        uri.append(endpoint);

        return new URI(uri.toString());
    }
}