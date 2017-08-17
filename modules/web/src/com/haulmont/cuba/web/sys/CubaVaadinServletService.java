/*
 * Copyright (c) 2008-2016 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.haulmont.cuba.web.sys;

import com.google.common.hash.HashCode;
import com.haulmont.cuba.core.global.*;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.web.App;
import com.haulmont.cuba.web.AppUI;
import com.haulmont.cuba.web.ScreenProfiler;
import com.haulmont.cuba.web.WebConfig;
import com.haulmont.cuba.web.auth.RequestContext;
import com.haulmont.cuba.web.auth.WebAuthConfig;
import com.haulmont.cuba.web.toolkit.ui.CubaFileUpload;
import com.vaadin.server.*;
import com.vaadin.server.communication.*;
import com.vaadin.ui.Component;
import com.vaadin.ui.UI;
import elemental.json.Json;
import elemental.json.JsonArray;
import elemental.json.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static com.google.common.hash.Hashing.md5;
import static org.apache.commons.io.IOUtils.copy;

public class CubaVaadinServletService extends VaadinServletService {

    private final Logger log = LoggerFactory.getLogger(CubaVaadinServletService.class);

    protected WebConfig webConfig;
    protected WebAuthConfig webAuthConfig;

    protected final String webResourceTimestamp;

    protected boolean testMode;

    public CubaVaadinServletService(VaadinServlet servlet, DeploymentConfiguration deploymentConfiguration)
            throws ServiceException {
        super(servlet, deploymentConfiguration);

        Configuration configuration = AppBeans.get(Configuration.NAME);
        webConfig = configuration.getConfig(WebConfig.class);
        webAuthConfig = configuration.getConfig(WebAuthConfig.class);
        testMode = configuration.getConfig(GlobalConfig.class).getTestMode();

        ServletContext sc = servlet.getServletContext();
        String resourcesTimestamp = sc.getInitParameter("webResourcesTs");
        if (StringUtils.isNotEmpty(resourcesTimestamp)) {
            this.webResourceTimestamp = resourcesTimestamp;
        } else {
            this.webResourceTimestamp = "DEBUG";
        }

        addSessionInitListener(event -> {
            WrappedSession wrappedSession = event.getSession().getSession();
            wrappedSession.setMaxInactiveInterval(webConfig.getHttpSessionExpirationTimeoutSec());

            HttpSession httpSession = wrappedSession instanceof WrappedHttpSession ? ((WrappedHttpSession) wrappedSession).getHttpSession() : null;
            log.debug("HttpSession {} initialized, timeout={}sec",
                    httpSession, wrappedSession.getMaxInactiveInterval());
        });

        addSessionDestroyListener(event -> {
            WrappedSession wrappedSession = event.getSession().getSession();
            HttpSession httpSession = wrappedSession instanceof WrappedHttpSession ? ((WrappedHttpSession) wrappedSession).getHttpSession() : null;
            log.debug("HttpSession destroyed: {}", httpSession);
            App app = event.getSession().getAttribute(App.class);
            if (app != null) {
                app.cleanupBackgroundTasks();
            }
        });

        setSystemMessagesProvider(systemMessagesInfo -> {
            Locale locale = systemMessagesInfo.getLocale();

            CustomizedSystemMessages msgs = new CustomizedSystemMessages();

            if (AppContext.isStarted()) {
                try {
                    Messages messages = AppBeans.get(Messages.NAME);

                    msgs.setInternalErrorCaption(messages.getMainMessage("internalErrorCaption", locale));
                    msgs.setInternalErrorMessage(messages.getMainMessage("internalErrorMessage", locale));

                    msgs.setCommunicationErrorCaption(messages.getMainMessage("communicationErrorCaption", locale));
                    msgs.setCommunicationErrorMessage(messages.getMainMessage("communicationErrorMessage", locale));

                    msgs.setSessionExpiredCaption(messages.getMainMessage("sessionExpiredErrorCaption", locale));
                    msgs.setSessionExpiredMessage(messages.getMainMessage("sessionExpiredErrorMessage", locale));
                } catch (Exception e) {
                    log.error("Unable to set system messages", e);
                    throw new RuntimeException("Unable to set system messages. " +
                            "It usually happens when the middleware web application is not responding due to " +
                            "errors on start. See logs for details.", e);
                }
            }

            String redirectUri;
            if (RequestContext.get() != null) {
                HttpServletRequest request = RequestContext.get().getRequest();
                redirectUri = StringUtils.replace(request.getRequestURI(), "/UIDL", "");
            } else {
                String webContext = AppContext.getProperty("cuba.webContextName");
                redirectUri = "/" + webContext;
            }

            msgs.setInternalErrorURL(redirectUri + "?restartApp");

            return msgs;
        });
    }

    @Override
    public String getConfiguredTheme(VaadinRequest request) {
        return webConfig.getAppWindowTheme();
    }

    @Override
    public String getApplicationVersion() {
        return webResourceTimestamp;
    }

    @Override
    protected List<RequestHandler> createRequestHandlers() throws ServiceException {
        List<RequestHandler> requestHandlers = super.createRequestHandlers();

        List<RequestHandler> cubaRequestHandlers = new ArrayList<>();

        for (RequestHandler handler : requestHandlers) {
            if (handler instanceof UidlRequestHandler) {
                // replace UidlRequestHandler with CubaUidlRequestHandler
                cubaRequestHandlers.add(new CubaUidlRequestHandler());
            } else if (handler instanceof PublishedFileHandler) {
                // replace PublishedFileHandler with CubaPublishedFileHandler
                // for support resources from VAADIN directory
                cubaRequestHandlers.add(new CubaPublishedFileHandler());
            } else if (handler instanceof ServletBootstrapHandler) {
                // replace ServletBootstrapHandler with CubaApplicationBootstrapHandler
                cubaRequestHandlers.add(new CubaServletBootstrapHandler());
            } else if (handler instanceof HeartbeatHandler) {
                // replace HeartbeatHandler with CubaHeartbeatHandler
                cubaRequestHandlers.add(new CubaHeartbeatHandler());
            } else if (handler instanceof FileUploadHandler) {
                // add support for jquery file upload
                cubaRequestHandlers.add(new FileUploadHandler());
                cubaRequestHandlers.add(new CubaFileUploadHandler());
            } else {
                cubaRequestHandlers.add(handler);
            }
        }

        cubaRequestHandlers.add(new CubaWebJarsHandler());

        return cubaRequestHandlers;
    }

    protected static class CubaWebJarsHandler implements RequestHandler {
        protected static final String APP_PUBLISHED_PREFIX = "/APP/PUBLISHED";
        protected static final String WEBJARS_PATH_PREFIX = "/webjars/";

        private final Logger log = LoggerFactory.getLogger(CubaWebJarsHandler.class);

        @Override
        public boolean handleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response) throws IOException {
            String path = request.getPathInfo();

            if (StringUtils.isEmpty(path) || StringUtils.isNotEmpty(path) && !path.startsWith(WEBJARS_PATH_PREFIX) &&
                    !path.startsWith(APP_PUBLISHED_PREFIX + WEBJARS_PATH_PREFIX))
                return false;

            path = path.replace(APP_PUBLISHED_PREFIX, "");

            log.trace("WebJar resource requested: {}", path);

            String errorMessage = checkResourcePath(path);
            if (StringUtils.isNotEmpty(errorMessage)) {
                log.error(errorMessage);
                response.sendError(HttpServletResponse.SC_FORBIDDEN, errorMessage);
                return false;
            }

            URL resourceUrl = getStaticResourceUrl(path);

            if (resourceUrl == null) {
                resourceUrl = getClassPathResourceUrl(path);
            }

            if (resourceUrl == null) {
                String msg = String.format("Requested WebJar resource is not found: %s", path);
                response.sendError(HttpServletResponse.SC_NOT_FOUND, msg);
                log.error(msg);
                return false;
            }

            String resourceName = getResourceName(path);
            String mimeType = VaadinServlet.getCurrent().getServletContext().getMimeType(resourceName);
            response.setContentType(mimeType != null ? mimeType : FileTypesHelper.DEFAULT_MIME_TYPE);

            String cacheControl = "public, max-age=0, must-revalidate";
            int resourceCacheTime = getCacheTime(resourceName);
            if (resourceCacheTime > 0) {
                cacheControl = "max-age=" + String.valueOf(resourceCacheTime);
            }
            response.setHeader("Cache-Control", cacheControl);
            response.setDateHeader("Expires", System.currentTimeMillis() + (resourceCacheTime * 1000));

            InputStream inputStream = null;
            try {
                URLConnection connection = resourceUrl.openConnection();
                long lastModifiedTime = connection.getLastModified();
                // Remove milliseconds to avoid comparison problems (milliseconds
                // are not returned by the browser in the "If-Modified-Since"
                // header).
                lastModifiedTime = lastModifiedTime - lastModifiedTime % 1000;
                response.setDateHeader("Last-Modified", lastModifiedTime);

                if (browserHasNewestVersion(request, lastModifiedTime)) {
                    response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                    return true;
                }

                inputStream = connection.getInputStream();

                copy(inputStream, response.getOutputStream());

                return true;
            } finally {
                if (inputStream != null) {
                    inputStream.close();
                }
            }
        }

        protected String getResourceName(String webjarsResourceURI) {
            String[] tokens = webjarsResourceURI.split("/");
            return tokens[tokens.length - 1];
        }

        // copy-pasted from VaadinServlet
        protected boolean browserHasNewestVersion(VaadinRequest request, long resourceLastModifiedTimestamp) {
            if (resourceLastModifiedTimestamp < 1) {
                // We do not know when it was modified so the browser cannot have an
                // up-to-date version
                return false;
            }
        /*
         * The browser can request the resource conditionally using an
         * If-Modified-Since header. Check this against the last modification
         * time.
         */
            try {
                // If-Modified-Since represents the timestamp of the version cached
                // in the browser
                long headerIfModifiedSince = request
                        .getDateHeader("If-Modified-Since");

                if (headerIfModifiedSince >= resourceLastModifiedTimestamp) {
                    // Browser has this an up-to-date version of the resource
                    return true;
                }
            } catch (Exception e) {
                // Failed to parse header. Fail silently - the browser does not have
                // an up-to-date version in its cache.
            }
            return false;
        }

        protected URL getStaticResourceUrl(String path) throws IOException {
            String staticPath = "/VAADIN/" + path;

            URL resourceUrl = VaadinServlet.getCurrent().getServletContext().getResource(staticPath);

            if (resourceUrl != null) {
                log.trace("Overridden version of WebJar resource found: {}", staticPath);
            }

            return resourceUrl;
        }

        protected URL getClassPathResourceUrl(String path) {
            String classpathPath = "/META-INF/resources" + path;

            log.trace("Load WebJar resource from classpath: {}", classpathPath);

            return this.getClass().getResource(classpathPath);
        }

        protected int getCacheTime(String filename) {
            if (filename.contains(".nocache.")) {
                return 0;
            }
            if (filename.contains(".cache.")) {
                return 60 * 60 * 24 * 365;
            }
            return 60 * 60;
        }

        protected String checkResourcePath(String url) {
            if (url.endsWith("/")) {
                return String.format("Directory loading is forbidden: %s", url);
            }

            if (url.contains("/../")) {
                return String.format("Loading WebJar resource with the upward path is forbidden: %s", url);
            }

            return null;
        }
    }

    // Add ability to load JS and CSS resources from VAADIN directory
    protected static class CubaPublishedFileHandler extends PublishedFileHandler {
        @Override
        protected InputStream getApplicationResourceAsStream(Class<?> contextClass, String fileName) {
            ServletContext servletContext = VaadinServlet.getCurrent().getServletContext();
            return servletContext.getResourceAsStream("/VAADIN/" + fileName);
        }
    }

    // Add support for CubaFileUpload component with XHR upload mechanism
    protected static class CubaFileUploadHandler extends FileUploadHandler {

        private final Logger log = LoggerFactory.getLogger(CubaFileUploadHandler.class);

        @Override
        protected boolean isSuitableUploadComponent(ClientConnector source) {
            if (!(source instanceof CubaFileUpload)) {
                // this is not jquery upload request
                return false;
            }

            log.trace("Uploading file using jquery file upload mechanism");

            return true;
        }

        @Override
        protected void sendUploadResponse(VaadinRequest request, VaadinResponse response,
                                          String fileName, long contentLength) throws IOException {
            JsonArray json = Json.createArray();
            JsonObject fileInfo = Json.createObject();
            fileInfo.put("name", fileName);
            fileInfo.put("size", contentLength);

            // just fake addresses and parameters
            fileInfo.put("url", fileName);
            fileInfo.put("thumbnail_url", fileName);
            fileInfo.put("delete_url", fileName);
            fileInfo.put("delete_type", "POST");
            json.set(0, fileInfo);

            PrintWriter writer = response.getWriter();
            writer.write(json.toJson());
            writer.close();
        }
    }

    /**
     * Add ability to redirect to base application URL if we have unparsable path tail
     */
    protected static class CubaServletBootstrapHandler extends ServletBootstrapHandler {
        @Override
        public boolean handleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response)
                throws IOException {
            String requestPath = request.getPathInfo();

            // redirect to base URL if we have unparsable path tail
            if (!StringUtils.equals("/", requestPath)) {
                response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
                response.setHeader("Location", request.getContextPath());

                return true;
            }

            return super.handleRequest(session, request, response);
        }
    }

    // Add ability to handle hearbeats in App
    protected static class CubaHeartbeatHandler extends HeartbeatHandler {
        private final Logger log = LoggerFactory.getLogger(CubaHeartbeatHandler.class);

        @Override
        public boolean synchronizedHandleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response)
                throws IOException {
            boolean result = super.synchronizedHandleRequest(session, request, response);

            if (log.isTraceEnabled()) {
                log.trace("Handle heartbeat {} {}", request.getRemoteHost(), request.getRemoteAddr());
            }

            if (result && App.isBound()) {
                App.getInstance().onHeartbeat();
            }

            return result;
        }
    }

    // Set security context to AppContext for normal UI requests
    protected static class CubaUidlRequestHandler extends UidlRequestHandler {
        private final Logger log = LoggerFactory.getLogger(CubaUidlRequestHandler.class);

        protected ScreenProfiler profiler = AppBeans.get(ScreenProfiler.NAME);

        protected static final String JAVASCRIPT_EXTENSION = ".js";
        protected static final String CSS_EXTENSION = ".css";

        @Override
        protected UidlWriter createUidlWriter() {
            return new UidlWriter() {
                @Override
                protected void writePerformanceData(UI ui, Writer writer) throws IOException {
                    super.writePerformanceData(ui, writer);

                    String profilerMarker = profiler.getCurrentProfilerMarker(ui);
                    if (profilerMarker != null) {
                        profiler.setCurrentProfilerMarker(ui, null);
                        long lastRequestTimestamp = ui.getSession().getLastRequestTimestamp();
                        writer.write(String.format(", \"profilerMarker\": \"%s\", \"profilerEventTs\": \"%s\", \"profilerServerTime\": %s",
                                profilerMarker, lastRequestTimestamp, System.currentTimeMillis() - lastRequestTimestamp));
                    }
                }

                @SuppressWarnings("deprecation")
                @Override
                protected void handleAdditionalDependencies(List<Class<? extends ClientConnector>> newConnectorTypes,
                                                            List<String> scriptDependencies, List<String> styleDependencies) {
                    LegacyCommunicationManager manager = AppUI.getCurrent().getSession().getCommunicationManager();

                    for (Class<? extends ClientConnector> connector : newConnectorTypes) {
                        WebJarResource webJarResource = connector.getAnnotation(WebJarResource.class);
                        if (webJarResource == null)
                            continue;

                        for (String uri : webJarResource.value()) {
                            uri = processResourceUri(uri);

                            if (uri.endsWith(JAVASCRIPT_EXTENSION)) {
                                scriptDependencies.add(manager.registerDependency(uri, connector));
                            }

                            if (uri.endsWith(CSS_EXTENSION)) {
                                styleDependencies.add(manager.registerDependency(uri, connector));
                            }
                        }
                    }
                }

                protected String processResourceUri(String uri) {
                    int propertyFirstIndex = uri.indexOf("${");
                    if (propertyFirstIndex == -1) {
                        return uri;
                    }

                    int propertyLastIndex = uri.indexOf("}");
                    String propertyName = uri.substring(propertyFirstIndex + 2, propertyLastIndex);

                    String webJarVersion = AppContext.getProperty(propertyName);

                    if (StringUtils.isEmpty(webJarVersion)) {
                        String msg = String.format("Could not load WebJar version property value: %s", propertyName);
                        log.error(msg);
                        throw new RuntimeException(msg);
                    }

                    return uri.replace("${" + propertyName + "}", webJarVersion);
                }
            };
        }
    }

    @Override
    protected VaadinSession createVaadinSession(VaadinRequest request) throws ServiceException {
        if (testMode && !webAuthConfig.getExternalAuthentication()) {
            return new VaadinSession(this) {
                @Override
                public String createConnectorId(ClientConnector connector) {
                    if (connector instanceof Component) {
                        Component component = (Component) connector;
                        String id = component.getId() == null ? super.createConnectorId(connector) : component.getId();
                        UserSession session = getAttribute(UserSession.class);

                        String login = null;
                        String locale = null;

                        if (session != null) {
                            login = session.getCurrentOrSubstitutedUser().getLogin();
                            if (session.getLocale() != null) {
                                locale = session.getLocale().toLanguageTag();
                            }
                        }

                        StringBuilder idParts = new StringBuilder();
                        if (login != null) {
                            idParts.append(login);
                        }
                        if (locale != null) {
                            idParts.append(locale);
                        }
                        idParts.append(id);

                        return toLongNumberString(idParts.toString());
                    }
                    return super.createConnectorId(connector);
                }

                protected String toLongNumberString(String data) {
                    HashCode hashCode = md5().hashString(data, StandardCharsets.UTF_8);
                    byte[] hashBytes = hashCode.asBytes();
                    byte[] shortBytes = new byte[Long.BYTES];

                    System.arraycopy(hashBytes, 0, shortBytes, 0, Long.BYTES);

                    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
                    buffer.put(shortBytes);
                    buffer.flip();
                    return Long.toString(Math.abs(buffer.getLong()));
                }
            };
        } else {
            return super.createVaadinSession(request);
        }
    }
}