package org.wso2.carbon.extension.identity.authenticator;

import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.wso2.carbon.extension.identity.authenticator.TeleSignAuthenticator.*;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.AUTHENTICATION;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.USER_NAME;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.AUTHENTICATE_USER;
import static org.wso2.carbon.extension.identity.helper.IdentityHelperConstants.SUPER_TENANT_DOMAIN;


@RunWith(PowerMockRunner.class)
@PrepareForTest({Util.class})
public class TeleSignAuthenticatorTest {
    private static final String NUMERIC_OTP = "1234";
    private static final String ALPHANUMERIC_OTP = "AB12";
    private static final String SAMPLE_MOBILE = "+94710830823";

    private TeleSignAuthenticator teleSignAuthenticator;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthenticationContext context;

    @Mock
    private ContextHandler contextHandler;

    @Mock
    private Util util;

    @BeforeMethod
    public void setUp() {
        teleSignAuthenticator = new TeleSignAuthenticator();
        initMocks(this);
    }

    /*
     * ============================================ CanHandle ============================================
     */
    @Test
    public void testCanHandle_OtpCodeEmptyAndResendCodeNotEmptyTrue() {
        when(request.getParameter(OTP_CODE)).thenReturn(null);
        when(request.getParameter(RESEND_CODE)).thenReturn(NUMERIC_OTP);
        Assert.assertTrue(teleSignAuthenticator.canHandle(request));
    }

    @Test
    public void testCanHandle_OtpCodeNotEmpty_True() {
        when(request.getParameter(OTP_CODE)).thenReturn(NUMERIC_OTP);
        Assert.assertTrue(teleSignAuthenticator.canHandle(request));
    }

    @Test
    public void testCanHandle_MobileNumberNotEmpty_True() {
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(SAMPLE_MOBILE);
        Assert.assertTrue(teleSignAuthenticator.canHandle(request));
    }

    @Test
    public void testCanHandle_OtpCodeEmptyAndResendCodeNotEmpty_False() {
        when(request.getParameter(OTP_CODE)).thenReturn(null);
        when(request.getParameter(RESEND_CODE)).thenReturn(null);
        Assert.assertFalse(teleSignAuthenticator.canHandle(request));
    }

    /*
     * ============================================ process ============================================
     */
    @Test
    public void testProcess_logout_SuccessCompleted() throws AuthenticationFailedException, LogoutFailedException {
        when(context.isLogoutRequest()).thenReturn(true);
        Assert.assertEquals(teleSignAuthenticator.process(
                request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcess_hasMobileNumber_Incomplete() throws AuthenticationFailedException, LogoutFailedException {
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(SAMPLE_MOBILE);
        Assert.assertEquals(teleSignAuthenticator.process(
                request, response, context), AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testProcess_hasOtpCode_Incomplete() throws AuthenticationFailedException, LogoutFailedException {
        when(request.getParameter(OTP_CODE)).thenReturn(NUMERIC_OTP);
        when(context.getProperty(AUTHENTICATION)).thenReturn(teleSignAuthenticator.getName());
        Assert.assertEquals(teleSignAuthenticator.process(
                request, response, context), AuthenticatorFlowStatus.INCOMPLETE);
        when(context.getProperty(AUTHENTICATION)).thenReturn(null);
        Assert.assertEquals(teleSignAuthenticator.process(
                request, response, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @AfterMethod
    public void tearDown() {
    }
}
