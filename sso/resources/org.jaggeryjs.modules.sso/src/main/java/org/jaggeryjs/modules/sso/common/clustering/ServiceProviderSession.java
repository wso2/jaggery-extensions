/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.jaggeryjs.modules.sso.common.clustering;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaggeryjs.hostobjects.web.SessionHostObject;
import org.jaggeryjs.modules.sso.common.constants.SSOConstants;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;

/**
 * Maintains the serviceProvider details against the relevant session
 */
public class ServiceProviderSession {

    private static final Log log = LogFactory.getLog(ClusteringUtil.class);
    private SessionHostObject session;
    private String serviceProvider;
    private String sessionId;

    public ServiceProviderSession(String serviceProvider, SessionHostObject session) {
        this.session = session;
        this.serviceProvider = serviceProvider;
        this.sessionId = ServiceProviderSession.getSessionId(session);
    }

    public String getServiceProvider() {
        return serviceProvider;
    }

    public String getSessionId() {
        return sessionId;
    }

    /**
     * A utility method to invoke the getId method of the provided SessionHostObject
     *
     * @param session A SessionHostObject
     * @return A unique String identifying the provided session
     */
    public static String getSessionId(SessionHostObject session) {
        Object[] args = new Object[0];
        String id = null;
        try {
            id = SessionHostObject.jsFunction_getId(null, session, args, null);
        } catch (ScriptException e) {
            log.error("Unable to invoke getId method of the Session HostObject.", e);
        }
        return id;
    }

    /**
     * Invalidates the session by calling the Session HostObjects invalidate method
     */
    public void invalidate() {
        Object[] args = new Object[0];
        try {
            SessionHostObject.jsFunction_invalidate(null, session, args, null);
        } catch (ScriptException e) {
            log.error("Unable to invalidate local session with ID : " + getSessionId(), e);
        }

    }

    public String toString() {
        return String.format(SSOConstants.ISSUER_SESSION_DETAILS, sessionId, serviceProvider);
    }
}
