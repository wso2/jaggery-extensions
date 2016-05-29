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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaggeryjs.hostobjects.web.SessionHostObject;
import org.jaggeryjs.modules.sso.common.clustering.ClusteringUtil;
import org.jaggeryjs.modules.sso.common.clustering.IssuerSession;
import org.jaggeryjs.modules.sso.common.clustering.IssuerSessionMap;
import org.jaggeryjs.modules.sso.common.clustering.SessionInvalidateClusterMessage;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Maintains the sessions of apps which are SSOed together against the IDP provided session index
 * It provides a set of convenience methods to Single Sign On and Single Logout.
 */
public class SSOSessionManager {
    private static final Log log = LogFactory.getLog(SSOSessionManager.class);
    /**
     * This map contains the idp session index mapped against the
     * sessions of applications which are SSOed together
     */
    private static Map<String, IssuerSessionMap> sessionHostObjectMap;
    private static Map<String, String> sessionToIDPIndexMap;
    //Eager instance creation to avoid concurrency issues
    private static SSOSessionManager instance = new SSOSessionManager();

    private SSOSessionManager() {
        sessionHostObjectMap = new ConcurrentHashMap<>();
        sessionToIDPIndexMap = new ConcurrentHashMap<>();
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
    public void login(String idpSessionIndex, String issuer, SessionHostObject session) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Trying to register issuer:%s ", issuer));
        }
        registerIssuerSessionWithIDPSessionIndex(idpSessionIndex, issuer, session);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished registering issuer:%s ", issuer));
        }
    }


    /**
     * Handles the Single Logout operation by invalidating the sessions mapped
     * to the provided IDP session index.
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response indicating IDP session index
     */
    public void logout(String idpSessionIndex, String issuer) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("trying to remove issuer:%s  using IDP Session Index", issuer));
        }
        removeIssuerSession(idpSessionIndex, issuer);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished removing issuer:%s using IDP Session Index ", issuer));
        }
    }

    /**
     * Handles the Single Logout operation by first resolving the session ID to a IDP session index
     *
     * @param session
     */
    public void logout(SessionHostObject session, String issuer) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Trying to remove issuer:%s using Session ", issuer));
        }

        String sessionId = IssuerSession.getSessionId(session);
        String idpSessionIndex = getIDPSessionIndex(sessionId);
        removeIssuerSession(idpSessionIndex, issuer);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished removing issuer:%s  using Session", issuer));
        }
    }

    /**
     * Removes issuer, session and IDP index details.This method should be called from a session destroy
     * listener.Please note that this method will not attempt to invalidate the session and will assume that
     * the session invalidate method has been already called.
     *
     * @param session
     * @param issuer
     */
    public void cleanUp(SessionHostObject session, String issuer) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Cleaning up session details of issuer: %s ", issuer));
        }
        String sessionId = IssuerSession.getSessionId(session);
        String idpSessionIndex = getIDPSessionIndex(sessionId);
        if (idpSessionIndex == null) {
            log.warn(String.format("Unable to locate an IDP Session Index for the provided session:%s .Aborting" +
                    " clean up operations.", sessionId));
            return;
        }
        IssuerSessionMap issuerMap = getIssuerSessionMap(idpSessionIndex);
        cleanUpIssuerMap(issuerMap, issuer);
        cleanUpLocalSessionDetails(sessionId);
        cleanUpIDPSessionDetails(idpSessionIndex, issuerMap);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished cleaning up session details of issuer :%s ", issuer));
        }
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
    public void logoutClusteredNodes(String idpSessionIndex, String issuer) {
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
        IssuerSession issuerSession = new IssuerSession(issuer, session);
        addToIssuerSessionMap(issuerSession, issuerSessionMap);

        String localSessionId = issuerSession.getSessionId();
        sessionToIDPIndexMap.put(localSessionId, idpSessionIndex);

        if (log.isDebugEnabled()) {

            log.debug(String.format("Registered Session Id: %s to IDP Session Index : %s", localSessionId, idpSessionIndex));
        }
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

            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex, issuer);
    }

    /**
     * Invalidates all local sessions mapped to the provided
     * IDP Session Index
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void removeIssuerSession(String idpSessionIndex, String issuer) {
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            notifyClusterToInvalidateSession(idpSessionIndex, issuer);
            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex, issuer);
    }

    /**
     * Ensures that data structures that track IDP session indices and local
     * session indices are freed up
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void cleanUpSessionsDetails(String idpSessionIndex, String issuer) {
        IssuerSessionMap issuerMap = getIssuerSessionMap(idpSessionIndex);
        invalidateIssuerSession(issuerMap, issuer);
        cleanUpIDPSessionDetails(idpSessionIndex, issuerMap);
    }

    /**
     * Removes the IDP session index to session mappings
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void cleanUpIDPSessionDetails(String idpSessionIndex, IssuerSessionMap issuerMap) {
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            return;
        }

        //We can only remove the idpSessionIndex if there are no valid sessions
        if (issuerMap.isEmpty()) {
            sessionHostObjectMap.remove(idpSessionIndex);

            if (log.isDebugEnabled()) {

                log.debug(String.format("Removed IDP Session Index %s since there  " +
                        "were no issuers", idpSessionIndex));
            }
        }
    }

    /**
     * Removes the local session to IDP session index mappings
     *
     * @param sessionId A string representing the local session ID
     */
    private void cleanUpLocalSessionDetails(String sessionId) {
        if (!sessionToIDPIndexMap.containsKey(sessionId)) {
            return;
        }
        sessionToIDPIndexMap.remove(sessionId);

        if (log.isDebugEnabled()) {

            log.debug(String.format("Removed issuer's Session Id:%s ", sessionId));
        }
    }

    private void cleanUpIssuerMap(IssuerSessionMap issuerMap, String issuer) {
        if (!issuerMap.containsKey(issuer)) {
            return;
        }
        issuerMap.remove(issuer);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Removed issuer:%s ", issuer));
        }
    }

    private void invalidateIssuerSession(IssuerSessionMap issuerMap, String issuer) {
        if (!issuerMap.containsKey(issuer)) {
            return;
        }

        IssuerSession issuerSession = issuerMap.getIssuerSession(issuer);
        String sessionId = issuerSession.getSessionId();
        issuerSession.invalidate();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Invalidated the issuer session :%s ", issuerSession));
        }

        cleanUpIssuerMap(issuerMap, issuer);
        cleanUpLocalSessionDetails(sessionId);
    }

    private IssuerSessionMap getIssuerSessionMap(String idpSessionIndex) {
        return sessionHostObjectMap.get(idpSessionIndex);
    }

    //TODO: Review this method (Should we synch this?)
    private IssuerSessionMap createIssuerSessionMap(String idpSessionIndex) {
        //Check if a session set exists
        IssuerSessionMap issuerMap = new IssuerSessionMap();
        sessionHostObjectMap.put(idpSessionIndex, issuerMap);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Registered new issuer map for IDP Session Index:%s ", idpSessionIndex));
        }
        return issuerMap;
    }

    //TODO: Review this method (Should we synch this?)
    private void addToIssuerSessionMap(IssuerSession issuerSession, IssuerSessionMap map) {
        map.addIssuerSession(issuerSession);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Registered issuer against Session: %s", issuerSession));
        }
    }

    /**
     * Maps the local session ID to a IDP session index
     *
     * @param sessionId
     * @return
     */
    private String getIDPSessionIndex(String sessionId) {
        //TODO:Add return description and a description for sessionId
        return sessionToIDPIndexMap.get(sessionId);
    }

    private void notifyClusterToInvalidateSession(String idpSessionIndex, String issuer) {
        SessionInvalidateClusterMessage message = new SessionInvalidateClusterMessage(idpSessionIndex, issuer);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Sending cluster message: %s ", message));
        }
        ClusteringUtil.sendClusterMessage(message);
    }
}
