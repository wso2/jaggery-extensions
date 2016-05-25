package org.jaggeryjs.modules.sso.common.clustering;

import org.jaggeryjs.hostobjects.web.SessionHostObject;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class IssuerSession {

    private static final Log log = LogFactory.getLog(ClusteringUtil.class);
    private SessionHostObject session;
    private String issuer;

    public IssuerSession( String issuer,SessionHostObject session) {
        this.session = session;
        this.issuer = issuer;
    }

    public String getIssuer(){
        return issuer;
    }

    public String getSessionId(){
        return IssuerSession.getSessionId(session);
    }

    public static String getSessionId(SessionHostObject session){
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
     * Obtains the local session ID by invoking the getId method
     * @return
     */
    public void invalidate(){
        //Check if the session has been already invalidated before attempting to invalidate
        Object[] args = new Object[0];
        try {
            SessionHostObject.jsFunction_invalidate(null, session, args, null);
        } catch (ScriptException e) {
            log.error("Unable to invalidate local session with ID : " + getSessionId(), e);
        }

    }
}
