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

import org.wso2.carbon.identity.authenticator.smsotp.SMSOTPConstants;

public class TeleSignAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "TeleSign";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "TeleSignAuthenticator";

    //TeleSign authorize endpoint URL
    public static final String TeleSign_OAUTH_ENDPOINT = "";
    //TeleSign token  endpoint URL
    public static final String TeleSign_TOKEN_ENDPOINT = "";
    //TeleSign user info endpoint URL
    public static final String TeleSign_USERINFO_ENDPOINT = "";

    public static final String MOBILE_NUMBER = SMSOTPConstants.MOBILE_NUMBER;
    public static final String CODE = SMSOTPConstants.CODE;
    public static final String AUTHENTICATION = SMSOTPConstants.AUTHENTICATION;
    public static final String SUPER_TENANT = SMSOTPConstants.SUPER_TENANT;
    public static final String AUTHENTICATED_USER = SMSOTPConstants.AUTHENTICATED_USER;

    private TeleSignAuthenticatorConstants() {
    }
}