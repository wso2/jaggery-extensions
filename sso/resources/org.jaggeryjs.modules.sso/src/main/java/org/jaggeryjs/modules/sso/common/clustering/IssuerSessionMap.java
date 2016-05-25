package org.jaggeryjs.modules.sso.common.clustering;

import org.jaggeryjs.hostobjects.web.SessionHostObject;

import java.util.HashMap;


public class IssuerSessionMap extends HashMap<String,IssuerSession> {

    public IssuerSession getIssuerSession(String issuer){
        return this.get(issuer);
    }

    public void addIssuerSession(String issuer,SessionHostObject session){
        this.put(issuer,new IssuerSession(issuer,session));
    }

    public void addIssuerSession(IssuerSession issuerSession){
        this.put(issuerSession.getIssuer(),issuerSession);
    }
}
