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

import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.Response;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.container.servlet.ServletResponse;
import org.xwiki.context.Execution;
import org.xwiki.contrib.webauthn.internal.endpoint.WebAuthnEndpoint;
import org.xwiki.resource.AbstractResourceReferenceHandler;
import org.xwiki.resource.ResourceReference;
import org.xwiki.resource.ResourceReferenceHandlerChain;
import org.xwiki.resource.ResourceReferenceHandlerException;
import org.xwiki.resource.ResourceType;

import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.servlet.ServletUtils;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiServletContext;
import com.xpn.xwiki.web.XWikiServletRequest;
import com.xpn.xwiki.web.XWikiServletResponse;

/**
 * WebAuthn entry point.
 *
 * @version $Id$
 */
@Component
@Named("webauthn")
@Singleton
public class WebAuthnResourceReferenceHandler extends AbstractResourceReferenceHandler<ResourceType>
{
    @Inject
    private Container container;

    @Inject
    private ComponentManager componentManager;

    @Inject
    private WebAuthnEndpoint unknown;

    @Inject
    private Execution execution;

    @Override
    public List<ResourceType> getSupportedResourceReferences()
    {
        return Arrays.asList(WebAuthnResourceReference.TYPE);
    }

    @Override
    public void handle(ResourceReference resourceReference, ResourceReferenceHandlerChain chain)
        throws ResourceReferenceHandlerException
    {
        WebAuthnResourceReference reference = (WebAuthnResourceReference) resourceReference;

        Request request = this.container.getRequest();

        if (!(request instanceof ServletRequest)) {
            throw new ResourceReferenceHandlerException("Unsupported request type [" + request.getClass() + "]");
        }

        HttpServletRequest httpServletRequest = ((ServletRequest) request).getHttpServletRequest();
        HttpServletResponse httpServletResponse = ((ServletResponse) request).getHttpServletResponse();

        iniitializeXWikiContext(httpServletRequest, httpServletResponse);

        try {
            handle(reference, httpServletRequest, httpServletResponse);
        } catch (Exception e) {
            throw new ResourceReferenceHandlerException("Failed to handle http servlet request", e);
        }

        // Be a good citizen, continue the chain, in case some lower-priority handler has something
        // to do with this resource reference
        chain.handleNext(reference);
    }



    protected void iniitializeXWikiContext(HttpServletRequest request, HttpServletResponse response)
        throws ResourceReferenceHandlerException
    {
        try {
            XWikiServletContext xwikiEngine = new  XWikiServletContext(request.getServletContext());
            XWikiServletRequest xwikiRequest = new XWikiServletRequest(request);
            XWikiServletResponse xwikiResponse = new XWikiServletResponse(response);

            // Create the XWikiContext
            XWikiContext context = Utils.prepareContext("", xwikiRequest, xwikiResponse, xwikiEngine);

            // Initialize the XWiki db. XWiki#getXWiki(XWikiContext) calls XWikiContext.setWiki(XWiki)
            XWiki xwiki = XWiki.getXWiki(context);

            // Initialize the URL factory
            context.setURLFactory(xwiki.getURLFactoryService().createURLFactory(context.getMode(), context));

            // Prepare the localized resources according to the selected languages
            xwiki.prepareResources(context);

            // Put the XWikiContext in the ExecutionContext
            context.declareInExecutionContext(this.execution.getContext());
        } catch (XWikiException e) {
            throw new ResourceReferenceHandlerException("Failed to initialize the XWiki context", e);
        }
    }

    private void handle(WebAuthnResourceReference reference, HttpServletRequest httpServletRequest,
        HttpServletResponse servletResponse) throws Exception
    {
        // Convert from Servlet http request to generic http request
        HttpRequest httpRequest = ServletUtils.makeHttpRequest(httpServletRequest);

        Response response;

        if (this.componentManager.hasComponent(WebAuthnEndpoint.class, reference.getEndpoint())) {
            WebAuthnEndpoint endpoint = this.componentManager.getInstance(WebAuthnEndpoint.class,
                reference.getPath());

            response = endpoint.handle(httpRequest, reference);
        } else {
            response = this.unknown.handle(httpRequest, reference);
        }

        // Response might be null if the handler already answered the client (for example
        // a redirect to the login screen
        if (response != null) {
            // Create http response
            HttpServletResponse httpResponse = (HttpServletResponse) response.getOutputStream();

            // Apply generic http response to Sevlet http response
            // ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
        }
    }
}
