package org.xwiki.contrib.webauthn.internal;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.webauthn.internal.util.ContentResponse;
import org.xwiki.template.TemplateManager;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;

@Component(roles = WebAuthn.class)
@Singleton
public class WebAuthn
{

    @Inject
    private TemplateManager templates;

    /**
     * Run a template and generate a HTML content response.
     *
     * @param templateName the name of the template
     * @return the HTML content response
     * @throws Exception when failing to execute the template
     */
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

