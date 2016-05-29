/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.jaggeryjs.modules.sso.common.constants;

public class SSOConstants {
    public static final String ERROR_CODE = "errorCode";

    public static final String IDP_URL = "identityProviderURL";
    public static final String KEY_STORE_NAME = "keyStoreName";
    public static final String KEY_STORE_PASSWORD = "keyStorePassword";
    public static final String IDP_ALIAS = "identityAlias";
    public static final String ISSUER_ID = "issuerId";

    public static final String IS_AUTHENTICATED = "authenticated";
    public static final String USERNAME = "username";

    public static final String SAML2_NAME_ID_POLICY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    public static final String LOGOUT_USER = "urn:oasis:names:tc:SAML:2.0:logout:user";
    public static final String CLUSTERING_MESSAGE = "SSOSessionInvalidationClusterMessage{issuer=%s,sessionIndex=%s}";
    public static final String ISSUER_SESSION_DETAILS = "ServiceProviderSession{sessionId=%s,issuer=%s}";
    public static final String SESSION_INVALIDATION_MESSAGE = "Invalidating session with idp session index=%s";

    public static final String OSGI_SERVICE_CONFIGURATION_CONTEXT = "org.wso2.carbon.utils.ConfigurationContextService";
    public static final int MAX_CLUSTER_MESSAGE_RETRY_COUNT = 4;
    public static final int CLUSTERING_MESSAGE_RETRY_DELAY = 2000;
    public static final boolean CLUSTERING_MESSAGE_ISRPC = true;

    public SSOConstants() {
    }
}
