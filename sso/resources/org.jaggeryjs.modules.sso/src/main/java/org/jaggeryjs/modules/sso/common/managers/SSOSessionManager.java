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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jaggeryjs.modules.sso.common.clustering.ClusteringUtil;
import org.jaggeryjs.modules.sso.common.clustering.IssuerSession;
import org.jaggeryjs.modules.sso.common.clustering.IssuerSessionMap;
import org.jaggeryjs.modules.sso.common.clustering.SessionInvalidateClusterMessage;
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
    private static Map<String, IssuerSessionMap> sessionHostObjectMap;
    private static Map<String, String> sessionToIDPIndexMap;
    private static SSOSessionManager instance = new SSOSessionManager();

    private SSOSessionManager() {
        sessionHostObjectMap = new ConcurrentHashMap<String,IssuerSessionMap>();
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
    public void login(String idpSessionIndex,String issuer,SessionHostObject session) {
        registerIssuerSessionWithIDPSessionIndex(idpSessionIndex, issuer, session);
    }


    /**
     * Handles the Single Logout operation by invalidating the sessions mapped
     * to the provided IDP session index.
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response indicating IDP session index
     */
    public void logout(String idpSessionIndex,String issuer) {
        removeIssuerSession(idpSessionIndex, issuer);
    }

    /**
     * Handles the Single Logout operation by first resolving the session ID to a IDP session index
     * @param session
     */
    public void logout(SessionHostObject session,String issuer){
        String sessionId = IssuerSession.getSessionId(session);
        String idpSessionIndex = getIDPSessionIndex(sessionId);
        removeIssuerSession(idpSessionIndex, issuer);
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
    public void logoutClusteredNodes(String idpSessionIndex,String issuer) {
        removeIssuerSessionInCluster(idpSessionIndex, issuer);
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
    private void registerIssuerSessionWithIDPSessionIndex(String idpSessionIndex, String issuer, SessionHostObject session) {
        IssuerSessionMap issuerSessionMap = getIssuerSessionMap(idpSessionIndex);
        if (issuerSessionMap == null) {
            issuerSessionMap = createIssuerSessionMap(idpSessionIndex);
        }
        IssuerSession issuerSession = new IssuerSession(issuer,session);
        addToIssuerSessionMap(issuerSession, issuerSessionMap);
        String localSessionId = issuerSession.getSessionId();
        sessionToIDPIndexMap.put(localSessionId,idpSessionIndex);
    }

    /**
     * Invalidates all local sessions mapped to the provided
     * IDP Session Index.If there is no locally recorded IDP session index it will
     * attempt to send a logout message to other nodes in the cluster
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void removeIssuerSessionInCluster(String idpSessionIndex, String issuer) {
        //If the IDP session index does not exist then attempt to notify
        //the other members of the cluster
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            notifyClusterToInvalidateSession(idpSessionIndex,issuer);
            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex,issuer);
    }

    /**
     * Invalidates all local sessions mapped to the provided
     * IDP Session Index
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void removeIssuerSession(String idpSessionIndex, String issuer) {
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex,issuer);
    }

    /**
     * Ensures that data structures that track IDP session indices and local
     * session indices are freed up
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void cleanUpSessionsDetails(String idpSessionIndex,String issuer) {
        IssuerSessionMap issuerMap = getIssuerSessionMap(idpSessionIndex);
        invalidateIssuerSession(issuerMap, issuer);
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

    private void invalidateIssuerSession(IssuerSessionMap issuerMap, String issuer) {
        if(!issuerMap.containsKey(issuer)){
            return;
        }
        IssuerSession issuerSession = issuerMap.getIssuerSession(issuer);
        String sessionId = issuerSession.getSessionId();
        issuerSession.invalidate();
        cleanUpLocalSessionDetails(sessionId);
    }

    private IssuerSessionMap getIssuerSessionMap(String idpSessionIndex) {
        return sessionHostObjectMap.get(idpSessionIndex);
    }

    private IssuerSessionMap createIssuerSessionMap(String idpSessionIndex) {
        //Check if a session set exists
        IssuerSessionMap issuerMap = new IssuerSessionMap();
        sessionHostObjectMap.put(idpSessionIndex, issuerMap);
        return issuerMap;
    }

    //TODO: Synch?
    private void addToIssuerSessionMap(IssuerSession issuerSession, IssuerSessionMap map) {
        map.addIssuerSession(issuerSession);
    }

    /**
     * Maps the local session ID to a IDP session index
     * @param sessionId
     * @return
     */
    private String getIDPSessionIndex(String sessionId){
        return sessionToIDPIndexMap.get(sessionId);
    }

    private void notifyClusterToInvalidateSession(String idpSessionIndex,String issuer) {
        ClusteringUtil.sendClusterMessage(new SessionInvalidateClusterMessage(idpSessionIndex,issuer));
    }
}
