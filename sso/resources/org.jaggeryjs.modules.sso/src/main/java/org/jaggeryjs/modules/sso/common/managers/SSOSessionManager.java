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

package org.jaggeryjs.modules.sso.common.managers;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jaggeryjs.modules.sso.common.clustering.ClusteringUtil;
import org.jaggeryjs.modules.sso.common.clustering.SessionInvalidateClusterMessage;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;
import org.jaggeryjs.hostobjects.web.SessionHostObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Maintains the sessions of apps which are SSOed together against the IDP provided session index
 * It provides a set of convenience methods to Single Sign On and Single Logout
 */
public class SSOSessionManager {
    private static final Log log = LogFactory.getLog(ClusteringUtil.class);
    /**
     * This map contains the idp session index mapped against the
     * sessions of applications which are SSOed together
     */
    private static Map<String, Set<SessionHostObject>> sessionHostObjectMap;
    private static Map<String,String> sessionToIDPIndexMap;
    private static SSOSessionManager instance = new SSOSessionManager();

    private SSOSessionManager() {
        sessionHostObjectMap = new ConcurrentHashMap<String, Set<SessionHostObject>>();
        sessionToIDPIndexMap = new ConcurrentHashMap<String,String>();
    }

    public static SSOSessionManager getInstance() {
        return instance;
    }

    /**
     * Registers the provided Session HostObject against the IDP session index.This
     * mapping is used to Single Logout all sessions when the logout method is called
     *
     * @param idpSessionIndex The IDP session index provided in the SAML login response
     * @param session         A Session HostObject
     */
    public void login(String idpSessionIndex, SessionHostObject session) {
        registerSessionWithIDPSessionIndex(idpSessionIndex, session);
    }

    /**
     * Handles the Single Logout operation by invalidating the sessions mapped
     * to the provided IDP session index.
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response indicating IDP session index
     */
    public synchronized void logout(String idpSessionIndex) {
        removeSessions(idpSessionIndex);
    }

    /**
     * Handles the Single Logout operation by first resolving the session ID to a IDP session index
     * @param session
     */
    public synchronized void logout(SessionHostObject session){
        String sessionId = getSessionId(session);
        String idpSessionIndex = getIDPSessionIndex(sessionId);
        removeSessions(idpSessionIndex);
    }

    /**
     * Handles the Single Logout operation by invalidating the sessions mapped
     * to the provided IDP session index.It will
     * attempt to notify all members with a message indicating that any sessions registered
     * against the provided IDP session index should be invalidated.
     * Note: Message delivery is not guaranteed but this method will attempt to retry
     * sending the message for a predefined retry count
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response indicating IDP session index
     */
    public void logoutClusteredNodes(String idpSessionIndex) {
        removeSessionsInCluster(idpSessionIndex);
    }

    /**
     * Performs a two way mapping of the IDP session index against the provided Session HostObject.
     * 1. Keeps a map of IDP session index against a set containing Session HostObjects
     * 2. Keeps a map of provided sessions against the IDP session index
     * This is useful since sometimes we need the IDP session index given the current session and vice versa
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     * @param session
     */
    private void registerSessionWithIDPSessionIndex(String idpSessionIndex, SessionHostObject session) {
        Set<SessionHostObject> sessionSet = getSessionSet(idpSessionIndex);
        if (sessionSet == null) {
            sessionSet = createSessionSet(idpSessionIndex);
        }
        addToSessionSet(session, sessionSet);
        String localSessionId = getSessionId(session);
        sessionToIDPIndexMap.put(localSessionId,idpSessionIndex);
    }

    /**
     * Invalidates all local sessions mapped to the provided
     * IDP Session Index.If there is no locally recorded IDP session index it will
     * attempt to send a logout message to other nodes in the cluster
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void removeSessionsInCluster(String idpSessionIndex) {
        //If the IDP session index does not exist then attempt to notify
        //the other members of the cluster
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            notifyClusterToInvalidateSession(idpSessionIndex);
            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex);
    }

    /**
     * Invalidates all local sessions mapped to the provided
     * IDP Session Index
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void removeSessions(String idpSessionIndex) {
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex);
    }

    /**
     * Ensures that data structures that track IDP session indices and local
     * session indices are freed up
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void cleanUpSessionsDetails(String idpSessionIndex) {
        Set<SessionHostObject> sessionSet = getSessionSet(idpSessionIndex);
        invalidateSessions(sessionSet);
        cleanUpIDPSessionDetails(idpSessionIndex);
    }

    /**
     * Removes the IDP session index to session mappings
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void cleanUpIDPSessionDetails(String idpSessionIndex){
        if(!sessionHostObjectMap.containsKey(idpSessionIndex)){
            return;
        }
        sessionHostObjectMap.remove(idpSessionIndex);
    }

    /**
     * Removes the local session to IDP session index mappings
     * @param sessionId  A string representing the local session ID
     */
    private void cleanUpLocalSessionDetails(String sessionId){
        if(!sessionToIDPIndexMap.containsKey(sessionId)){
            return;
        }
        sessionToIDPIndexMap.remove(sessionId);
    }

    private void invalidateSessions(Set<SessionHostObject> sessionSet) {
        log.info("Invalidating sessions");
        log.info("Set size: " + sessionSet.size());
        for (SessionHostObject session : sessionSet) {
            invalidateSession(session);
        }
        log.info("Finished invalidating sessions");
    }

    private void invalidateSession(SessionHostObject session) {
        String localSessionId = getSessionId(session);
        if (localSessionId == null) {
            log.error("Unable to invalidate session since the session ID could not be resolved from the provided " +
                    "session");
            return;
        }

        //Check if the session has been already invalidated before attempting to invalidate
        Object[] args = new Object[0];
        try {
            log.info("Invalidating session " + localSessionId);
            SessionHostObject.jsFunction_invalidate(null, session, args, null);
            //Remove the sessionIndex
            cleanUpLocalSessionDetails(localSessionId);
        } catch (ScriptException e) {
            log.error("Unable to invalidate local session with ID : " + localSessionId, e);
        }

    }

    private Set<SessionHostObject> getSessionSet(String idpSessionIndex) {
        return sessionHostObjectMap.get(idpSessionIndex);
    }

    private Set<SessionHostObject> createSessionSet(String idpSessionIndex) {
        //Check if a session set exists
        Set<SessionHostObject> set = new HashSet<SessionHostObject>();
        sessionHostObjectMap.put(idpSessionIndex, set);
        return set;
    }

    //TODO: Synch?
    private void addToSessionSet(SessionHostObject session, Set<SessionHostObject> sessionSet) {
        sessionSet.add(session);
    }

    /**
     * Obtains the local session ID by invoking the getId method
     * @param session
     * @return
     */
    private String getSessionId(SessionHostObject session) {
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
     * Maps the local session ID to a IDP session index
     * @param sessionId
     * @return
     */
    private String getIDPSessionIndex(String sessionId){
        return sessionToIDPIndexMap.get(sessionId);
    }

    private void notifyClusterToInvalidateSession(String idpSessionIndex) {
        ClusteringUtil.sendClusterMessage(new SessionInvalidateClusterMessage(idpSessionIndex));
    }
}
