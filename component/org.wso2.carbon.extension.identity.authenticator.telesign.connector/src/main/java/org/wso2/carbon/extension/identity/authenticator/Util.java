package org.wso2.carbon.extension.identity.authenticator;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

class Util {
    private static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";

    static boolean isParameterEmpty(HttpServletRequest request, String param) {
        return StringUtils.isEmpty(request.getParameter(param));
    }

    static boolean isParameterNotEmpty(HttpServletRequest request, String param) {
        return StringUtils.isNotEmpty(request.getParameter(param));
    }

    static boolean doesUserExistInUserStore(String username) throws AuthenticationFailedException, UserStoreException {
        return FederatedAuthenticatorUtil.isUserExistInUserStore(username);
    }

    static Map<String, String> getParamsMapFromApplicationAuthenticationXml(String authenticatorName) {
        AuthenticatorConfig config = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(authenticatorName);
        if (config == null) {
            return Collections.emptyMap();
        }
        return config.getParameterMap();
    }

    private static String getTenantDomain(String username) {
        return MultitenantUtils.getTenantDomain(username);
    }

    static String getTenantAwareUsername(String username) {
        return MultitenantUtils.getTenantAwareUsername(username);
    }

    static UserRealm getUserRealm(String username) throws UserStoreException {
        int tenantId = IdentityTenantUtil.getTenantId(getTenantDomain(username));
        return IdentityTenantUtil
                .getRealmService()
                .getTenantUserRealm(tenantId);
    }

    static String getMobileNumber(String username) throws UserStoreException {
        UserRealm userRealm = getUserRealm(username);
        /* TODO: is userRealm null check necessary? */
        return userRealm.getUserStoreManager().getUserClaimValue(
                getTenantAwareUsername(username), MOBILE_CLAIM, null);
    }

    static boolean isBasicAuthentication(ContextHandler contextHandler) {
        AuthenticationContext context = contextHandler.getContext();
        ApplicationAuthenticator applicationAuthenticator = context
                .getSequenceConfig()
                .getStepMap()
                .get(context.getCurrentStep() - 1)
                .getAuthenticatedAutenticator()
                .getApplicationAuthenticator();
        return applicationAuthenticator instanceof LocalApplicationAuthenticator;
    }

    static void updateLocalAuthenticatedUserInStepConfig(ContextHandler contextHandler) {
        FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(
                contextHandler.getContext(), contextHandler.getAuthenticatedUser());
    }
}
