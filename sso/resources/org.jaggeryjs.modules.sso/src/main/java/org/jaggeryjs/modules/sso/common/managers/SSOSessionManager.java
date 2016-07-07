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
import org.jaggeryjs.modules.sso.common.clustering.ServiceProviderMap;
import org.jaggeryjs.modules.sso.common.clustering.ServiceProviderSession;
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
    private static Map<String, ServiceProviderMap> sessionHostObjectMap;
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
    public void login(String idpSessionIndex, String serviceProvider, SessionHostObject session) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Trying to register Service Provider:%s ", serviceProvider));
        }
        registerServiceProviderSessionWithIDPSessionIndex(idpSessionIndex, serviceProvider, session);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished registering Service Provider:%s ", serviceProvider));
        }
    }


    /**
     * Handles the Single Logout operation by invalidating the sessions mapped
     * to the provided IDP session index.
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response indicating IDP session index
     */
    public void logout(String idpSessionIndex, String serviceProvider) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Trying to remove Service Provider:%s  using IDP Session Index", serviceProvider));
        }
        removeServiceProviderSession(idpSessionIndex, serviceProvider);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished removing Service Provider:%s using IDP Session Index ", serviceProvider));
        }
    }

    /**
     * Handles the Single Logout operation by first resolving the session ID to a IDP session index
     *
     * @param session
     */
    public void logout(SessionHostObject session, String serviceProvider) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Trying to remove Service Provider:%s using Session ", serviceProvider));
        }

        String sessionId = ServiceProviderSession.getSessionId(session);
        String idpSessionIndex = getIDPSessionIndex(sessionId);
        removeServiceProviderSession(idpSessionIndex, serviceProvider);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished removing ServiceProvider:%s  using Session", serviceProvider));
        }
    }

    /**
     * Removes the Service Provider session and IDP index details.This method should be called from a session destroy
     * listener.Please note that this method will not attempt to invalidate the session and will assume that
     * the session invalidate method has been already called.
     *
     * @param session
     * @param serviceProvider
     */
    public void cleanUp(SessionHostObject session, String serviceProvider) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Cleaning up session details of Service Provider: %s ", serviceProvider));
        }
        String sessionId = ServiceProviderSession.getSessionId(session);
        String idpSessionIndex = getIDPSessionIndex(sessionId);
        if (idpSessionIndex == null) {
            if (log.isDebugEnabled()) {
                log.warn(String.format("Unable to locate an IDP Session Index for the provided session:%s .Aborting" +
                        " clean up operations.", sessionId));
            }
            return;
        }
        ServiceProviderMap serviceProviderMap = getServiceProviderSessionMap(idpSessionIndex);
        cleanUpSessionProviderMap(serviceProviderMap, serviceProvider);
        cleanUpLocalSessionDetails(sessionId);
        cleanUpIDPSessionDetails(idpSessionIndex, serviceProviderMap);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Finished cleaning up session details of Service Provider :%s ", serviceProvider));
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
    public void logoutClusteredNodes(String idpSessionIndex, String serviceProvider) {
        removeServiceProviderSessionInCluster(idpSessionIndex, serviceProvider);
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
    private void registerServiceProviderSessionWithIDPSessionIndex(String idpSessionIndex, String serviceProvider,
                                                                   SessionHostObject session) {
        ServiceProviderMap serviceProviderSessionMap = getServiceProviderSessionMap(idpSessionIndex);
        if (serviceProviderSessionMap == null) {
            serviceProviderSessionMap = createServiceProviderSessionMap(idpSessionIndex);
        }
        ServiceProviderSession serviceProviderSession = new ServiceProviderSession(serviceProvider, session);
        addToServiceProviderSessionMap(serviceProviderSession, serviceProviderSessionMap);

        String localSessionId = serviceProviderSession.getSessionId();
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
    private void removeServiceProviderSessionInCluster(String idpSessionIndex, String serviceProvider) {
        //If the IDP session index does not exist then attempt to notify
        //the other members of the cluster
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {

            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex, serviceProvider);
    }

    /**
     * Invalidates all local sessions mapped to the provided
     * IDP Session Index
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void removeServiceProviderSession(String idpSessionIndex, String serviceProvider) {
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            notifyClusterToInvalidateSession(idpSessionIndex, serviceProvider);
            //There is nothing else to do as the idpSessionIndex does not
            //contain any sessions
            return;
        }
        cleanUpSessionsDetails(idpSessionIndex, serviceProvider);
    }

    /**
     * Ensures that data structures that track IDP session indices and local
     * session indices are freed up
     *
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private void cleanUpSessionsDetails(String idpSessionIndex, String serviceProvider) {
        ServiceProviderMap serviceProviderMap = getServiceProviderSessionMap(idpSessionIndex);
        invalidateServiceProviderSession(serviceProviderMap, serviceProvider);
        cleanUpIDPSessionDetails(idpSessionIndex, serviceProviderMap);
    }

    /**
     * Removes the IDP session index to session mappings
     * Note: This method needs to be synched as the service providers maybe removed from multiple applications at the
     * same time.
     * @param idpSessionIndex A String key which is provided in the SAML login response  indicating IDP session index
     */
    private synchronized void cleanUpIDPSessionDetails(String idpSessionIndex, ServiceProviderMap serviceProviderMap) {
        if (!sessionHostObjectMap.containsKey(idpSessionIndex)) {
            return;
        }

        //We can only remove the idpSessionIndex if there are no valid sessions
        if (serviceProviderMap.isEmpty()) {
            sessionHostObjectMap.remove(idpSessionIndex);

            if (log.isDebugEnabled()) {

                log.debug(String.format("Removed IDP Session Index %s since there  " +
                        "were no Service Providers", idpSessionIndex));
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

            log.debug(String.format("Removed Service Provider's Session Id:%s ", sessionId));
        }
    }

    private void cleanUpSessionProviderMap(ServiceProviderMap serviceProviderMap, String serviceProvider) {
        if (!serviceProviderMap.containsKey(serviceProvider)) {
            return;
        }
        serviceProviderMap.remove(serviceProvider);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Removed Service Provider:%s ", serviceProvider));
        }
    }

    private void invalidateServiceProviderSession(ServiceProviderMap serviceProviderMap, String serviceProvider) {
        if (!serviceProviderMap.containsKey(serviceProvider)) {
            return;
        }

        ServiceProviderSession serviceProviderSession = serviceProviderMap.getServiceProviderSession(serviceProvider);
        String sessionId = serviceProviderSession.getSessionId();
        serviceProviderSession.invalidate();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Invalidated the Service Provider session :%s ", serviceProviderSession));
        }

        cleanUpSessionProviderMap(serviceProviderMap, serviceProvider);
        cleanUpLocalSessionDetails(sessionId);
    }

    private ServiceProviderMap getServiceProviderSessionMap(String idpSessionIndex) {
        return sessionHostObjectMap.get(idpSessionIndex);
    }

    private ServiceProviderMap createServiceProviderSessionMap(String idpSessionIndex) {
        //Check if a session set exists
        ServiceProviderMap serviceProviderMap = new ServiceProviderMap();
        sessionHostObjectMap.put(idpSessionIndex, serviceProviderMap);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Registered new Service Provider map for IDP Session Index:%s ", idpSessionIndex));
        }
        return serviceProviderMap;
    }

    private void addToServiceProviderSessionMap(ServiceProviderSession serviceProviderSession, ServiceProviderMap map) {
        map.addServiceProviderSession(serviceProviderSession);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Registered Service Provider against Session: %s", serviceProviderSession));
        }
    }

    private String getIDPSessionIndex(String sessionId) {
        return sessionToIDPIndexMap.get(sessionId);
    }

    private void notifyClusterToInvalidateSession(String idpSessionIndex, String serviceProvider) {
        SessionInvalidateClusterMessage message = new SessionInvalidateClusterMessage(idpSessionIndex, serviceProvider);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Sending cluster message: %s ", message));
        }
        ClusteringUtil.sendClusterMessage(message);
    }
}
