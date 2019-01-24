package org.wso2.carbon.extension.identity.authenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TeleSignUseCase {
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final ContextWrapper contextWrapper;
    private final ApplicationAuthenticationXmlProps xmlProps;

    public interface RequestStep {
        ResponseStep request(HttpServletRequest request);
    }

    public interface ResponseStep {
        ContextWrapperStep response(HttpServletResponse response);
    }

    public interface ContextWrapperStep {
        XmlPropsStep contextWrapper(ContextWrapper contextWrapper);
    }

    public interface XmlPropsStep {
        Build xmlConfig(ApplicationAuthenticationXmlProps xmlProps);
    }

    public interface Build {
        TeleSignUseCase build();
    }

    public static class Builder implements RequestStep, ResponseStep, ContextWrapperStep, XmlPropsStep, Build {
        private HttpServletRequest request;
        private HttpServletResponse response;
        private ContextWrapper contextWrapper;
        private ApplicationAuthenticationXmlProps xmlProps;

        @Override
        public ResponseStep request(HttpServletRequest request) {
            this.request = request;
            return this;
        }

        @Override
        public ContextWrapperStep response(HttpServletResponse response) {
            this.response = response;
            return this;
        }

        @Override
        public XmlPropsStep contextWrapper(ContextWrapper contextWrapper) {
            this.contextWrapper = contextWrapper;
            return this;
        }

        @Override
        public Build xmlConfig(ApplicationAuthenticationXmlProps xmlProps) {
            this.xmlProps = xmlProps;
            return this;
        }

        @Override
        public TeleSignUseCase build() {
            return new TeleSignUseCase(this);
        }
    }

    private TeleSignUseCase(Builder builder) {
        this.request = builder.request;
        this.response = builder.response;
        this.contextWrapper = builder.contextWrapper;
        this.xmlProps = builder.xmlProps;
    }
}
