/*
 * Copyright (c) 2008-2017 Haulmont.
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
 */

package com.haulmont.restapi.ldap;

import com.haulmont.cuba.core.global.Configuration;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;
import java.security.Principal;
import java.util.*;

@RestController
public class LdapAuthController implements InitializingBean {

    protected LdapTemplate defaultLdapTemplate;
    protected LdapContextSource defaultLdapContextSource;

    protected LdapContextSource ldapContextSource;
    protected LdapTemplate ldapTemplate;
    protected String ldapUserLoginField;

    @Inject
    protected Configuration configuration;

    protected Set<HttpMethod> allowedRequestMethods = Collections.singleton(HttpMethod.POST);

    @RequestMapping(value = "/ldap/token", method= RequestMethod.GET)
    public ResponseEntity<OAuth2AccessToken> getAccessToken(Principal principal, @RequestParam
            Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        if (!allowedRequestMethods.contains(HttpMethod.GET)) {
            throw new HttpRequestMethodNotSupportedException("GET");
        }

        return postAccessToken(principal, parameters);
    }

    @RequestMapping(value = "/ldap/token", method = RequestMethod.POST)
    public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal,
                                                             @RequestParam Map<String, String> parameters)
            throws HttpRequestMethodNotSupportedException {

        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException(
                    "There is no client authentication. Try adding an appropriate authentication filter.");
        }

        // todo implement
        throw new NotImplementedException();

        /*if (!ldapTemplate.authenticate(LdapUtils.emptyLdapName(), buildPersonFilter(login), password)) {
            throw new LoginException(
                    messages.formatMessage(LdapAuthProvider.class, "LoginException.InvalidLoginOrPassword", messagesLocale, login)
            );
        }*/
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        RestLdapConfig ldapConfig = configuration.getConfig(RestLdapConfig.class);

        checkRequiredConfigProperties(ldapConfig);

        defaultLdapContextSource = createLdapContextSource(ldapConfig);
        defaultLdapTemplate = createLdapTemplate(defaultLdapContextSource);
        if (ldapContextSource == null) {
            ldapContextSource = defaultLdapContextSource;
        }
        if (ldapTemplate == null) {
            ldapTemplate = defaultLdapTemplate;
        }
        if (ldapUserLoginField == null) {
            ldapUserLoginField = ldapConfig.getLdapUserLoginField();
        }
    }

    protected LdapTemplate createLdapTemplate(LdapContextSource ldapContextSource) {
        LdapTemplate ldapTemplate = new LdapTemplate(ldapContextSource);
        ldapTemplate.setIgnorePartialResultException(true);

        return ldapTemplate;
    }

    protected LdapContextSource createLdapContextSource(RestLdapConfig ldapConfig) {
        LdapContextSource ldapContextSource = new LdapContextSource();

        ldapContextSource.setBase(ldapConfig.getLdapBase());
        List<String> ldapUrls = ldapConfig.getLdapUrls();
        ldapContextSource.setUrls(ldapUrls.toArray(new String[ldapUrls.size()]));
        ldapContextSource.setUserDn(ldapConfig.getLdapUser());
        ldapContextSource.setPassword(ldapConfig.getLdapPassword());

        ldapContextSource.afterPropertiesSet();

        return ldapContextSource;
    }

    protected void checkRequiredConfigProperties(RestLdapConfig ldapConfig) {
        List<String> missingProperties = new ArrayList<>();
        if (StringUtils.isBlank(ldapConfig.getLdapBase())) {
            missingProperties.add("cuba.web.ldap.base");
        }
        if (ldapConfig.getLdapUrls().isEmpty()) {
            missingProperties.add("cuba.web.ldap.urls");
        }
        if (StringUtils.isBlank(ldapConfig.getLdapUser())) {
            missingProperties.add("cuba.web.ldap.user");
        }
        if (StringUtils.isBlank(ldapConfig.getLdapPassword())) {
            missingProperties.add("cuba.web.ldap.password");
        }

        if (!missingProperties.isEmpty()) {
            throw new IllegalStateException("Please configure required application properties for LDAP integration: \n" +
                    StringUtils.join(missingProperties, "\n"));
        }
    }

    protected String buildPersonFilter(String login) {
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("objectclass", "person"))
                .and(new EqualsFilter(ldapUserLoginField, login));
        return filter.encode();
    }

    public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
        this.allowedRequestMethods = allowedRequestMethods;
    }

    public LdapContextSource getLdapContextSource() {
        return ldapContextSource;
    }

    public void setLdapContextSource(LdapContextSource ldapContextSource) {
        this.ldapContextSource = ldapContextSource;
    }

    public LdapTemplate getLdapTemplate() {
        return ldapTemplate;
    }

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public String getLdapUserLoginField() {
        return ldapUserLoginField;
    }

    public void setLdapUserLoginField(String ldapUserLoginField) {
        this.ldapUserLoginField = ldapUserLoginField;
    }
}