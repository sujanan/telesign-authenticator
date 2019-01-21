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

class ContextHandler {
    private final AuthenticationContext context;

    ContextHandler(AuthenticationContext context) {
        this.context = context;
    }

    boolean isLogoutRequest() {
        return context.isLogoutRequest();
    }

    boolean isRetrying() {
        return context.isRetrying();
    }

    AuthenticatedUser getAuthenticatedUser() {
        return (AuthenticatedUser) context.getProperty(AUTHENTICATE_USER);
    }

    String getAuthenticatorName() {
        return String.valueOf(context.getProperty(AUTHENTICATION));
    }

    String getUsername() {
        return String.valueOf(context.getProperty(USER_NAME));
    }

    String getQueryParamsWithFrameworkContextId() {
        return FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(),
                context.getCallerSessionKey(),
                context.getContextIdentifier());
    }

    private String getTenantDomain() {
        return context.getTenantDomain();
    }

    void setAuthenticatorName(String name) {
        context.setProperty(AUTHENTICATION, name);
    }

    void addUsernameFromFirstStepToContext() throws AuthenticationFailedException {
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
    }

    ApplicationAuthenticationXmlConfig getInstanceOfApplicationAuthenticationXmlConfig(String authenticatorName)
            throws AuthenticationFailedException {
        return new ApplicationAuthenticationXmlConfig(authenticatorName);
    }

    class ApplicationAuthenticationXmlConfig {
        private static final String OTP_MANDATORY = "OtpMandatory";

        private final Map<String, String> configMap;

        private ApplicationAuthenticationXmlConfig(String authenticatorName) throws AuthenticationFailedException {
            if (!getTenantDomain().equals(SUPER_TENANT_DOMAIN)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(
                        context,
                        authenticatorName,
                        getTenantDomain());
            }
            configMap = Util.getParamsMapFromApplicationAuthenticationXml(authenticatorName);
        }

        private String getConfiguration(String configName) {
            Object propertyFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
            String tenantDomain = getTenantDomain();
            if ((propertyFromLocal != null) || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)
                    && configMap.containsKey(configName)) {
                return configMap.get(configName);
            } else if ((context.getProperty(configName)) != null) {
                return String.valueOf(context.getProperty(configName));
            }
            return null;
        }

        boolean isOtpMandatory() {
            return Boolean.parseBoolean(getConfiguration(OTP_MANDATORY));
        }
    }

    AuthenticationContext getContext() {
        return context;
    }

}
