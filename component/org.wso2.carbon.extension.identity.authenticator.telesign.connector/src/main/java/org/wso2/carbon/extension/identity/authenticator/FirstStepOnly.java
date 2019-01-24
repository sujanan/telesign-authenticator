package org.wso2.carbon.extension.identity.authenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FirstStepOnly implements UseCaseChain {
    private UseCaseChain nextChain;

    @Override
    public void setNextChain(UseCaseChain nextChain) {
        this.nextChain = nextChain;
    }

    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response,
                        ContextWrapper contextWrapper,
                        ContextWrapper.ApplicationAuthenticationXmlHelper xmlConfig) {
    }
}
