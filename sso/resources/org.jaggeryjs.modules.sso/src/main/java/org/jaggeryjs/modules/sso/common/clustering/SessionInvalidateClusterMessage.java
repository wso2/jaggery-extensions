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

import org.apache.axis2.clustering.ClusteringCommand;
import org.apache.axis2.clustering.ClusteringFault;
import org.apache.axis2.clustering.ClusteringMessage;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaggeryjs.modules.sso.common.constants.SSOConstants;
import org.jaggeryjs.modules.sso.common.managers.SSOSessionManager;

public class SessionInvalidateClusterMessage extends ClusteringMessage {
    private static final Log log = LogFactory.getLog(SessionInvalidateClusterMessage.class);
    private String idpSessionIndex;

    public SessionInvalidateClusterMessage(String idpSessionIndex) {
        super();
        this.idpSessionIndex = idpSessionIndex;
    }

    @Override
    public ClusteringCommand getResponse() {
        return null;//TODO: What can we do here?
    }

    @Override
    public void execute(ConfigurationContext configurationContext) throws ClusteringFault {
        if (log.isDebugEnabled()) {
            log.debug(String.format(SSOConstants.SESSION_INVALIDATION_MESSAGE, idpSessionIndex));
        }
        SSOSessionManager.getInstance().logout(idpSessionIndex);
    }

    public String toString() {
        return String.format(SSOConstants.CLUSTERING_MESSAGE, idpSessionIndex);
    }
}
