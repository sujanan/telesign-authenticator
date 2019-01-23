package org.wso2.carbon.extension.identity.authenticator;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;

public interface UseCaseChain {

    void setNextChain(UseCaseChain nextChain);

    void process(HttpRequest request,
                 HttpResponse response,
                 ContextWrapper contextWrapper,
                 ContextWrapper.ApplicationAuthenticationXmlConfig xmlConfig);
}
