/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *
 */

package org.jaggeryjs.modules.oauth;

import com.google.gson.annotations.SerializedName;

public class ProviderConfig {

    private Float oauth_version;
    private String authorization_url;
    private String access_token_url;
    private String request_token_url;
    private String callback_url;
    private String api_key;
    private String api_secret;

    public ProviderConfig() {
    }

    public Float getOAuth_version() {
        return oauth_version;
    }

    public void setOAuth_version(Float oauth_version) {
        this.oauth_version = oauth_version;
    }

    public String getAuthorization_url() {
        return authorization_url;
    }

    public void setAuthorization_url(String authorization_url) {
        this.authorization_url = authorization_url;
    }

    public String getAccess_token_url() {
        return access_token_url;
    }

    public void setAccess_token_url(String access_token_url) {
        this.access_token_url = access_token_url;
    }

    public String getRequest_token_url() {
        return request_token_url;
    }

    public void setRequest_token_url(String request_token_url) {
        this.request_token_url = request_token_url;
    }

    public String getCallback_url() {
        return callback_url;
    }

    public void setCallback_url(String callback_url) {
        this.callback_url = callback_url;
    }

    public String getApi_key() {
        return api_key;
    }

    public void setApi_key(String api_key) {
        this.api_key = api_key;
    }

    public String getApi_secret() {
        return api_secret;
    }

    public void setApi_secret(String api_secret) {
        this.api_secret = api_secret;
    }
}
