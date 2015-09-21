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

package org.jaggeryjs.modules.oauth.bean;

import com.google.gson.Gson;

public class AccessTokenResponse {

    private AccessTokenResponseConfig accessTokenResponseConfig;

    public AccessTokenResponse(AccessTokenResponseConfig atrc){
        this.accessTokenResponseConfig = atrc;
    }

    public String getAccessToken(){
        return accessTokenResponseConfig.getAccess_token();
    }

    public void setAccessToken(String accessToken){
        accessTokenResponseConfig.setAccess_token(accessToken);
    }

    public String getRefreshToken(){
        return accessTokenResponseConfig.getRefresh_token();
    }

    public void setRefreshToken(String refreshToken){
        accessTokenResponseConfig.setRefresh_token(refreshToken);
    }

    public String getTokenType() {
        return accessTokenResponseConfig.getToken_type();
    }

    public void setTokenType(String tokenType) {
        accessTokenResponseConfig.setToken_type(tokenType);
    }

    public String getExpiresIn() {
        return accessTokenResponseConfig.getExpires_in();
    }

    public void setExpiresIn(String expiresIn) {
        accessTokenResponseConfig.setExpires_in(expiresIn);
    }

    @Override
    public String toString() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }
}
