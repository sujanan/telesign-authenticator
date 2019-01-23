package org.wso2.carbon.extension.identity.authenticator;

import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Map;

import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.AUTHENTICATION;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.USER_NAME;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.AUTHENTICATE_USER;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.SUPER_TENANT_DOMAIN;

public class ContextWrapper {
    private final AuthenticationContext context;

    public ContextWrapper(AuthenticationContext context) {
        this.context = context;
    }

    public boolean isLogoutRequest() {
        return context.isLogoutRequest();
    }

    public boolean isRetrying() {
        return context.isRetrying();
    }

    public String getAuthenticatorName() {
        return String.valueOf(context.getProperty(AUTHENTICATION));
    }

    public String getUsername() {
        return String.valueOf(context.getProperty(USER_NAME));
    }

    public String getQueryParamsWithFrameworkContextId() {
        return FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(),
                context.getCallerSessionKey(),
                context.getContextIdentifier());
    }

    private String getTenantDomain() {
        return context.getTenantDomain();
    }

    public AuthenticatedUser getAuthenticatedUser() {
        return (AuthenticatedUser) context.getProperty(AUTHENTICATE_USER);
    }

    public Object getLocalProperty() {
        return context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
    }

    public void setAuthenticatorName(String name) {
        context.setProperty(AUTHENTICATION, name);
    }

    public void addUsernameFromFirstStepToContext() throws AuthenticationFailedException {
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
    }

    public ApplicationAuthenticationXmlConfig getInstanceOfApplicationAuthenticationXmlConfig(String authenticatorName)
            throws AuthenticationFailedException {
        String tenantDomain = getTenantDomain();
        if (!tenantDomain.equals(SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(
                    context,
                    authenticatorName,
                    tenantDomain);
        }
        return new ApplicationAuthenticationXmlConfig(authenticatorName, tenantDomain, getLocalProperty());
    }

    public static class ApplicationAuthenticationXmlConfig {
        private final String tenantDomain;
        private final Object localProperty;
        private final Map<String, String> configMap;

        private ApplicationAuthenticationXmlConfig(String authenticatorName, String tenantDomain, Object localProperty)
                throws AuthenticationFailedException {
            this.tenantDomain = tenantDomain;
            this.localProperty = localProperty;
            configMap = Util.getParamsMapFromApplicationAuthenticationXml(authenticatorName);
        }

        private String getConfiguration(String configName) {
            if (canGetConfig(configName)) {
                return configMap.get(configName);
            }
            return null;
        }

        private boolean canGetConfig(String configName) {
            boolean b1 = localProperty != null;
            boolean b2 = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)
                    && configMap.containsKey(configName);
            return b1 || b2;
        }
    }

    public AuthenticationContext getContext() {
        return context;
    }

}
