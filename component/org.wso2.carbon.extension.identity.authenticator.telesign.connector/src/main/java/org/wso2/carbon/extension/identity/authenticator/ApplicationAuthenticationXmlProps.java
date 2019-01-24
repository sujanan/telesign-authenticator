package org.wso2.carbon.extension.identity.authenticator;

public class ApplicationAuthenticationXmlProps {
    private static final String OTP_MANDATORY = "otpMandatory";
    private static final String OTP_ENABLED = "otpEnabled";
    private static final String OTP_TO_MOBILE = "otpToMobile";
    private static final String OTP_TO_FEDERATED_MOBILE = "otpToFederatedMobile";
    private static final String RESEND_CODE_ENABLED = "resendCodeEnabled";
    private static final String RETRY_ENABLED = "retryEnabled";
    private static final String ALPHA_NUMERIC = "alphaNumeric";
    private static final String TOKEN_EXPIRY_TIME = "tokenExpiryTime";
    private static final String TOKEN_LENGTH = "tokenLength";
    private static final String ERROR_PAGE = "errorPage";
    private static final String REDIRECT_PAGE = "redirectPage";

    private final boolean otpMandatory;
    private final boolean otpEnabled;
    private final boolean otpToMobile;
    private final boolean otpToFederatedMobile;
    private final boolean resendCodeEnabled;
    private final boolean retryEnabled;
    private final boolean alphaNumeric;
    private final String tokenExpiryTime;
    private final String tokenLength;
    private final String errorPage;
    private final String redirectPage;

    public static class Builder {
        private final ContextWrapper.ApplicationAuthenticationXmlHelper xmlHelper;
        private String otpMandatoryProp;
        private String otpEnabledProp;
        private String otpToMobileProp;
        private String otpToFederatedMobileProp;
        private String resendCodeEnabledProp;
        private String retryEnabledProp;
        private String alphaNumericProp;
        private String tokenExpiryTimeProp;
        private String tokenLengthProp;
        private String errorPageProp;
        private String redirectPageProp;

        public Builder(ContextWrapper.ApplicationAuthenticationXmlHelper xmlHelper) {
            this.xmlHelper = xmlHelper;
        }

        public Builder otpMandatoryProp(String name) {
            otpMandatoryProp = name;
            return this;
        }

        public Builder otpEnabledProp(String name) {
            otpEnabledProp = name;
            return this;
        }

        public Builder otpToMobileProp(String name) {
            otpToMobileProp = name;
            return this;
        }

        public Builder otpToFederatedMobileProp(String name) {
            otpToFederatedMobileProp = name;
            return this;
        }

        public Builder resendCodeEnabledProp(String name) {
            resendCodeEnabledProp = name;
            return this;
        }

        public Builder retryEnabledProp(String name) {
            retryEnabledProp = name;
            return this;
        }

        public Builder alphaNumericProp(String name) {
            alphaNumericProp = name;
            return this;
        }

        public Builder tokenExpiryTimeProp(String name) {
            tokenExpiryTimeProp = name;
            return this;
        }

        public Builder tokenLengthProp(String name) {
            tokenLengthProp = name;
            return this;
        }

        public Builder errorPageProp(String name) {
            errorPageProp = name;
            return this;
        }

        public Builder redirectPageProp(String name) {
            redirectPageProp = name;
            return this;
        }

        public ApplicationAuthenticationXmlProps build() {
            return new ApplicationAuthenticationXmlProps(xmlHelper, this);
        }
    }

    private ApplicationAuthenticationXmlProps(ContextWrapper.ApplicationAuthenticationXmlHelper xmlHelper,
                                              Builder builder) {
        otpMandatory = toBoolean(xmlHelper.getConfiguration(
                assign(builder.otpMandatoryProp, OTP_MANDATORY)));
        otpEnabled = toBoolean(xmlHelper.getConfiguration(
                assign(builder.otpEnabledProp, OTP_ENABLED)));
        otpToMobile = toBoolean(xmlHelper.getConfiguration(
                assign(builder.otpToMobileProp, OTP_TO_MOBILE)));
        otpToFederatedMobile = toBoolean(xmlHelper.getConfiguration(
                assign(builder.otpToFederatedMobileProp, OTP_TO_FEDERATED_MOBILE)));
        resendCodeEnabled = toBoolean(xmlHelper.getConfiguration(
                assign(builder.resendCodeEnabledProp, RESEND_CODE_ENABLED)));
        retryEnabled = toBoolean(xmlHelper.getConfiguration(
                assign(builder.retryEnabledProp, RETRY_ENABLED)));
        alphaNumeric = toBoolean(xmlHelper.getConfiguration(
                assign(builder.alphaNumericProp, ALPHA_NUMERIC)));
        tokenExpiryTime = xmlHelper.getConfiguration(
                assign(builder.tokenExpiryTimeProp, TOKEN_EXPIRY_TIME));
        tokenLength = xmlHelper.getConfiguration(
                assign(builder.tokenLengthProp, TOKEN_LENGTH));
        errorPage = xmlHelper.getConfiguration(
                assign(builder.errorPageProp, ERROR_PAGE));
        redirectPage = xmlHelper.getConfiguration(
                assign(builder.redirectPageProp, REDIRECT_PAGE));
    }

    private String assign(String prop, String defaultProp) {
        if (prop == null) {
            return defaultProp;
        }
        return prop;
    }

    private boolean toBoolean(String prop) {
        return Boolean.parseBoolean(prop);
    }
}
