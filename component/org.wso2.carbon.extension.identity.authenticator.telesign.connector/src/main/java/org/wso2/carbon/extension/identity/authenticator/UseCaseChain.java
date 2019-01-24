package org.wso2.carbon.extension.identity.authenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface UseCaseChain {

    void setNextChain(UseCaseChain nextChain);

    void process(HttpServletRequest request,
                 HttpServletResponse response,
                 ContextWrapper contextWrapper,
                 ContextWrapper.ApplicationAuthenticationXmlHelper xmlConfig);
}
