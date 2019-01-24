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
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus.INCOMPLETE;
import static org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus.SUCCESS_COMPLETED;

/**
 * A scalable abstract Authenticator for TeleSign APIs in WSO2 Identity Server.
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
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        ContextWrapper contextWrapper = new ContextWrapper(context);
        if (contextWrapper.isLogoutRequest()) {
            return SUCCESS_COMPLETED;
        }
        if (Util.isParameterNotEmpty(request, MOBILE_NUMBER)) {
            initiateAuthenticationRequest(request, response, context);
            return INCOMPLETE;
        }
        if (Util.isParameterNotEmpty(request, OTP_CODE)) {
            initiateAuthenticationRequest(request, response, context);
            if (contextWrapper.getAuthenticatorName().equals(getName())) {
                return INCOMPLETE;
            }
            return SUCCESS_COMPLETED;
        }
        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        ContextWrapper contextWrapper = new ContextWrapper(context);
        /* Set authenticator name */
        contextWrapper.setAuthenticatorName(getName());
        /* Add first step username to context */
        contextWrapper.addUsernameFromFirstStepToContext();
        /* No need to process if no authenticated user found */
        if (contextWrapper.getAuthenticatedUser() == null) {
            throw new AuthenticationFailedException("Authentication failed: no authenticated user found.");
        }
        TeleSignUseCase useCase = new TeleSignUseCase.Builder()
                .request(request)
                .response(response)
                .contextWrapper(contextWrapper)
                .xmlProps(getApplicationAuthenticationXmlProps(
                        contextWrapper.getInstanceOfApplicationAuthenticationXmlHelper(getName()), context))
                .build();
    }

    protected ApplicationAuthenticationXmlProps getApplicationAuthenticationXmlProps(
            ContextWrapper.ApplicationAuthenticationXmlHelper xmlHelper, AuthenticationContext context) {
        return new ApplicationAuthenticationXmlProps.Builder(xmlHelper, context).build();
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
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
}

