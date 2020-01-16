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

package com.haulmont.cuba.portal.sys;

import com.google.common.base.Strings;
import com.haulmont.bali.util.ParamsMap;
import com.haulmont.cuba.client.sys.UsersRepository;
import com.haulmont.cuba.core.global.*;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.core.sys.SecurityContext;
import com.haulmont.cuba.portal.App;
import com.haulmont.cuba.portal.Connection;
import com.haulmont.cuba.portal.ConnectionListener;
import com.haulmont.cuba.portal.config.PortalConfig;
import com.haulmont.cuba.portal.security.PortalSession;
import com.haulmont.cuba.portal.sys.security.PortalSecurityContext;
import com.haulmont.cuba.portal.sys.security.PortalSessionFactory;
import com.haulmont.cuba.security.app.TrustedClientService;
import com.haulmont.cuba.security.auth.*;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.SessionParams;
import com.haulmont.cuba.security.global.UserSession;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.util.*;

public class PortalConnection implements Connection {

    private static final Logger log = LoggerFactory.getLogger(Connection.class);

    protected final List<ConnectionListener> listeners = new ArrayList<>();

    protected volatile boolean connected;

    protected volatile PortalSession session;

    @Inject
    protected PortalConfig portalConfig;
    @Inject
    protected Configuration configuration;
    @Inject
    protected AuthenticationService authenticationService;
    @Inject
    protected PortalSessionFactory portalSessionFactory;
    @Inject
    protected Messages messages;
    @Inject
    protected UsersRepository usersRepository;
    @Inject
    protected PasswordEncryption passwordEncryption;
    @Inject
    protected TrustedClientService trustedClientService;

    protected static final String MSG_PACK = "com.haulmont.cuba.portal.security";

    @Override
    public synchronized void login(String login, String password, Locale locale,
                                   @Nullable String ipAddress, @Nullable String clientInfo) throws LoginException {

        UserSession userSession = doLogin(login, password, locale, ipAddress, clientInfo, getSessionParams(ipAddress, clientInfo));

        session = portalSessionFactory.createPortalSession(userSession, locale);
        session.setAuthenticated(true);

        // replace security context
        PortalSecurityContext portalSecurityContext = new PortalSecurityContext(session);
        portalSecurityContext.setPortalApp(App.getInstance());

        // middleware service is called just below
        AppContext.setSecurityContext(portalSecurityContext);

        connected = true;
        fireConnectionListeners();
    }

    /**
     * Forward login logic to {@link com.haulmont.cuba.security.auth.AuthenticationService}.
     * Can be overridden to change login logic.
     *
     * @param login      login name
     * @param password   encrypted password
     * @param locale     client locale
     * @param ipAddress  user IP address
     * @param clientInfo client info
     * @return created user session
     * @throws LoginException in case of unsuccessful login
     */
    protected UserSession doLogin(String login, String password, Locale locale, @Nullable String ipAddress, @Nullable String clientInfo,
                                  Map<String, Object> params) throws LoginException {
        LoginPasswordCredentials credentials = new LoginPasswordCredentials(login, password, locale);
        credentials.setParams(params);
        credentials.setClientType(ClientType.PORTAL);
        if (ipAddress != null)
            credentials.setIpAddress(ipAddress);
        if (clientInfo != null)
            credentials.setClientInfo(clientInfo);
        credentials.setSecurityScope(portalConfig.getSecurityScope());

        if (portalConfig.getCheckPasswordOnClient()) {
            return loginClient(credentials).getSession();
        } else {
            return loginMiddleware(credentials).getSession();
        }
    }

    protected AuthenticationDetails loginMiddleware(LoginPasswordCredentials credentials) throws LoginException {
        return authenticationService.login(credentials);
    }

    protected AuthenticationDetails loginClient(LoginPasswordCredentials credentials) {
        String login = credentials.getLogin();

        Locale credentialsLocale = credentials.getLocale() == null ?
                messages.getTools().getDefaultLocale() : credentials.getLocale();

        if (Strings.isNullOrEmpty(login)) {
            // empty login is not valid
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        UserSession systemSession = trustedClientService.getSystemSession(portalConfig.getTrustedClientPassword());
        User user = AppContext.withSecurityContext(new SecurityContext(systemSession), () -> usersRepository.findUserByLogin(login));

        if (user == null) {
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        if (!passwordEncryption.checkPassword(user, credentials.getPassword())) {
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        return authenticationService.login(createTrustedCredentials(credentials));
    }

    protected TrustedClientCredentials createTrustedCredentials(LoginPasswordCredentials credentials) {
        TrustedClientCredentials tcCredentials = new TrustedClientCredentials(
                credentials.getLogin(),
                portalConfig.getTrustedClientPassword(),
                credentials.getLocale(),
                credentials.getParams()
        );

        tcCredentials.setClientInfo(credentials.getClientInfo());
        tcCredentials.setClientType(ClientType.PORTAL);
        tcCredentials.setIpAddress(credentials.getIpAddress());
        tcCredentials.setOverrideLocale(credentials.isOverrideLocale());
        tcCredentials.setSyncNewUserSessionReplication(credentials.isSyncNewUserSessionReplication());
        tcCredentials.setSessionAttributes(credentials.getSessionAttributes());
        tcCredentials.setSecurityScope(credentials.getSecurityScope());

        return tcCredentials;
    }

    protected String getInvalidCredentialsMessage(String login, Locale locale) {
        return messages.formatMessage(MSG_PACK, "LoginException.InvalidLoginOrPassword", locale, login);
    }

    protected Map<String, Object> getSessionParams(@Nullable String ipAddress, @Nullable String clientInfo) {
        GlobalConfig globalConfig = configuration.getConfig(GlobalConfig.class);
        String serverInfo = "Portal (" +
                globalConfig.getWebHostName() + ":" +
                globalConfig.getWebPort() + "/" +
                globalConfig.getWebContextName() + ") ";
        return ParamsMap.of(
                ClientType.class.getName(), AppContext.getProperty("cuba.clientType"),
                SessionParams.IP_ADDRESS.getId(), ipAddress != null ? ipAddress : "unknown",
                SessionParams.CLIENT_INFO.getId(), serverInfo + (clientInfo != null ? clientInfo : "")
        );
    }

    @Override
    public synchronized void login(Locale locale, @Nullable String ipAddress, @Nullable String clientInfo) throws LoginException {
        // get anonymous session
        session = portalSessionFactory.createPortalSession(null, locale);

        // replace security context
        PortalSecurityContext portalSecurityContext = new PortalSecurityContext(session);
        portalSecurityContext.setPortalApp(App.getInstance());

        // middleware service is called just below
        AppContext.setSecurityContext(portalSecurityContext);
        if (StringUtils.isNotBlank(ipAddress)) {
            session.setAddress(ipAddress);
        }
        if (StringUtils.isNotBlank(clientInfo)) {
            session.setClientInfo(clientInfo);
        }
        connected = true;
    }

    @Override
    public synchronized void logout() {
        try {
            authenticationService.logout();
            AppContext.setSecurityContext(null);
        } catch (Exception e) {
            log.warn("Error on logout", e);
        }

        connected = false;
        try {
            fireConnectionListeners();
        } catch (LoginException e) {
            log.warn("Error on logout", e);
        }
        session = null;
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public PortalSession getSession() {
        return session;
    }

    @Override
    public synchronized void update(PortalSession session) throws LoginException {
        internalLogout();

        this.session = session;
        connected = true;

        try {
            internalLogin();
        } catch (LoginException e) {
            internalLogout();
            throw e;
        } catch (Exception e) {
            internalLogout();
            throw new RuntimeException("Unable to perform internal login", e);
        }
    }

    protected void internalLogin() throws LoginException {
        PortalSecurityContext securityContext = new PortalSecurityContext(session);
        securityContext.setPortalApp(App.getInstance());

        AppContext.setSecurityContext(securityContext);

        fireConnectionListeners();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Logged in: user=%s", session.getUser().getLogin()));
        }
    }

    protected void internalLogout() {
        if (session != null && session.isAuthenticated()) {
            authenticationService.logout();
        }

        AppContext.setSecurityContext(null);

        connected = false;
        session = null;
    }

    @Override
    public void addListener(ConnectionListener listener) {
        synchronized (listeners) {
            if (!listeners.contains(listener))
                listeners.add(listener);
        }
    }

    @Override
    public void removeListener(ConnectionListener listener) {
        synchronized (listeners) {
            listeners.remove(listener);
        }
    }

    private void fireConnectionListeners() throws LoginException {
        List<ConnectionListener> activeListeners;
        synchronized (listeners) {
            activeListeners = new ArrayList<>(listeners);
        }

        for (ConnectionListener listener : activeListeners) {
            listener.connectionStateChanged(this);
        }
    }
}