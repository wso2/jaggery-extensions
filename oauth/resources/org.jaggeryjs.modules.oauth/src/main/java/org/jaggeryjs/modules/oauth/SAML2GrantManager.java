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

import org.apache.commons.io.IOUtils;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;

public class SAML2GrantManager {

    private static final String assertionStartMarker = "<saml2:Assertion";
    private static final String assertionEndMarker = "</saml2:Assertion>";

    /**
     * Returns access token details that can be used to extract access token, refresh token, token type and expires in
     *
     * @param targetURL token endpoint url
     * @param urlParameters parameter with grant type and assertion string
     * @param clientCredentials api key and api secret
     * @return access token details Json string
     */
    public static String executePost(String targetURL, String urlParameters, String clientCredentials)
            throws ScriptException {

        URL url;
        HttpURLConnection connection = null;
        try {
            //Create connection
            url = new URL(targetURL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("Authorization", "Basic " + clientCredentials);

            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);

            //Send request
            OutputStream writer = connection.getOutputStream();
            writer.write(urlParameters.getBytes());
            writer.close();

            //Get Response
            InputStream reader = connection.getInputStream();
            String response = IOUtils.toString(reader, "UTF-8");
            IOUtils.closeQuietly(reader);

            return response;
        } catch (MalformedURLException ex) {
            throw new ScriptException("The target URL is not valid.", ex);
        } catch (ProtocolException ex) {
            throw new ScriptException("The protocol is not valid.", ex);
        } catch (IOException ex) {
            throw new ScriptException("The request cannot be sent.", ex);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Returns assertion string
     *
     * @param SAMLResponse decoded SAML response string
     * @return assertion string
     */
    public static String getSamlAssertionString(String SAMLResponse) throws ScriptException {
        int assertionStartIndex = SAMLResponse.indexOf(assertionStartMarker);
        int assertionEndIndex = SAMLResponse.indexOf(assertionEndMarker);
        if (assertionStartIndex != -1 && assertionEndIndex != -1) {
            return SAMLResponse.substring(assertionStartIndex, assertionEndIndex) + assertionEndMarker;
        } else {
            throw new ScriptException("Invalid SAML response. SAML response has no valid assertion string.");
        }
    }
}
