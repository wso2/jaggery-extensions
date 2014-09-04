package org.jaggeryjs.modules.oauth;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConfig;
import org.scribe.utils.Preconditions;

import org.scribe.utils.*;

import java.util.HashMap;
import java.util.Map;


public class GenericOAuth20Api extends DefaultApi20 {
    private String AUTHORIZE_URL;
    private String ACCESS_TOKEN_EP;
    private String CALLBACK_URL;
    private HashMap<String, String> AUTHORIZE_PARAMS;

	public void setAuthorizeUrl(String authorizeUrl) {
        this.AUTHORIZE_URL = authorizeUrl;
    }

    public void setAccessTokenEP(String accessTokenEP) {
        this.ACCESS_TOKEN_EP = accessTokenEP;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return this.ACCESS_TOKEN_EP;
    }
    
    public String getCallBackUrl() {
		return CALLBACK_URL;
	}

	public void setCallBackUrl(String cALLBACK_URL) {
		CALLBACK_URL = cALLBACK_URL;
	}

    public HashMap<String, String> getAuthorizeParams() {
        return AUTHORIZE_PARAMS;
    }

    public void setAuthorizeParams(HashMap authirizeParams) {
        this.AUTHORIZE_PARAMS = authirizeParams;
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {
        Preconditions.checkValidUrl(getCallBackUrl(), "Must provide a valid url as callback.");

        String authorizeUrl = AUTHORIZE_URL
                    + "?client_id=" + config.getApiKey()
                    + "&response_type=code"
                    + "&redirect_uri=" + OAuthEncoder.encode(getCallBackUrl());

        // Append additional authorizing_params if present
        if (getAuthorizeParams() != null) {
            for (Map.Entry<String, String> entry : getAuthorizeParams().entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                authorizeUrl += "&" + key + "=" + OAuthEncoder.encode(value);
            }
        }

        return authorizeUrl;
    }
}
