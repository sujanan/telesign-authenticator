/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.extension.identity.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.authenticator.ContextHandler.ApplicationAuthenticationXmlConfig;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.user.api.UserStoreException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus.INCOMPLETE;
import static org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus.SUCCESS_COMPLETED;

/**
 * Authenticator of TeleSign
 */
public class TeleSignAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {
    /* HttpServletRequest parameter key values */
    static final String RESEND_CODE = "resendCode";
    static final String OTP_CODE = "OTPCode";
    static final String MOBILE_NUMBER = "MOBILE_NUMBER";

    private static Log log = LogFactory.getLog(TeleSignAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        boolean resendCodeNotEmpty = Util.isParameterNotEmpty(request, RESEND_CODE);
        boolean otpCodeNotEmpty = Util.isParameterNotEmpty(request, OTP_CODE);
        boolean mobileNumberNotEmpty = Util.isParameterNotEmpty(request, MOBILE_NUMBER);

        return (!otpCodeNotEmpty && resendCodeNotEmpty) || otpCodeNotEmpty || mobileNumberNotEmpty;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        ContextHandler contextHandler = new ContextHandler(context);
        if (contextHandler.isLogoutRequest()) {
            return SUCCESS_COMPLETED;
        }
        if (Util.isParameterNotEmpty(request, MOBILE_NUMBER)) {
            initiateAuthenticationRequest(request, response, context);
            return INCOMPLETE;
        }
        if (Util.isParameterNotEmpty(request, OTP_CODE)) {
            initiateAuthenticationRequest(request, response, context);
            if (contextHandler.getAuthenticatorName().equals(getName())) {
                return INCOMPLETE;
            }
            return SUCCESS_COMPLETED;
        }
        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            ContextHandler contextHandler = new ContextHandler(context);
            contextHandler.setAuthenticatorName(getName());

            contextHandler.addUsernameFromFirstStepToContext();
            /* Current user */
            AuthenticatedUser user = contextHandler.getAuthenticatedUser();
            if (user == null) {
                throw new AuthenticationFailedException("Authentication failed: no authenticated user found.");
            }
            ApplicationAuthenticationXmlConfig xmlConfig =
                    contextHandler.getInstanceOfApplicationAuthenticationXmlConfig(getName());
            boolean otpMandatory = xmlConfig.isOtpMandatory();
            boolean userExists = Util.doesUserExistInUserStore(user.getUserName());
        } catch (UserStoreException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    @Override
    public String getName() {
        return "TeleSignAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "TeleSign Authenticator";
    }

    /* ================================================== CASES ================================================== */

    private void caseOtpMandatory(ContextHandler contextHandler, HttpServletRequest request) {
        if (contextHandler.isRetrying() && Util.isParameterNotEmpty(request, RESEND_CODE)) {

        }
    }

    private void caseFirstStepOnly(ContextHandler contextHandler) {
        if (Util.isBasicAuthentication(contextHandler)) {
            updateToBasicAuthentication(contextHandler);
        }
    }

    private void updateToBasicAuthentication(ContextHandler contextHandler) {
        Util.updateLocalAuthenticatedUserInStepConfig(contextHandler);
        contextHandler.setAuthenticatorName("basic");
    }

}

