package org.jaggeryjs.modules.ws;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.description.WSDL2Constants;
import org.apache.axis2.namespace.Constants;
import org.apache.axis2.util.XMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.wso2.carbon.CarbonException;
import org.jaggeryjs.modules.ws.util.XSLTTransformer;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;
import org.jaggeryjs.scriptengine.util.HostObjectUtil;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Result;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class WSStubHostObject extends ScriptableObject {
    private static Log log = LogFactory.getLog(WSStubHostObject.class);
    private static final String hostObjectName = "WSStub";

    private Object services;
    private Object webService;

    private String jsString = "";

    public WSStubHostObject() {
    }

    @Override
    public String getClassName() {
        return hostObjectName;
    }

    public static Scriptable jsConstructor(Context cx, Object[] args, Function thisObj,
                                           boolean inNewExpr) throws ScriptException {
        if (args.length != 1) {
            HostObjectUtil.invalidNumberOfArgs(
                    hostObjectName, "Constructor", 1, true);
        } else {
            WSStubHostObject wsStub = new WSStubHostObject();
            String jsStubString = wsStub.genarateStubFromURL("e4x", (String) args[0]);

            Scriptable scope = thisObj;

            cx.evaluateString(scope, jsStubString, "(wso2)", 1, null);

            wsStub.services = scope.get("services", scope);

            if (wsStub.services == Scriptable.NOT_FOUND) {
                log.error("Error creating stub, services not found");
            }

            wsStub.webService = scope.get("WebService", scope);

            if (wsStub.webService == Scriptable.NOT_FOUND) {
                log.error("Error creating stub, WebService not found");
            }

            return wsStub;

        }
        return null;
    }

    public Scriptable jsGet_services() {
        return (Scriptable) services;
    }

    public Scriptable jsGet_webService() {
        return (Scriptable) webService;
    }

    /**
     * Given a uri to a WSDL this operation returns the JavaScript stub for that service
     *
     * @param type - dom or e4x
     * @param url  - URL to the WSDL document
     * @return - The JavaScript stub as a String
     * @throws CarbonException - Thrown in case an exception occurs
     */
    public String genarateStubFromURL(String type, String url) throws ScriptException {
        InputStream inputStream;
        try {
            URL wsdlURL = new URL(url);
            inputStream = wsdlURL.openStream();
            return getStub(type, readStream(inputStream), url);
        } catch (IOException e) {
            throw new ScriptException(e);
        }
    }

    private ByteArrayOutputStream readStream(InputStream ins) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = ins.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }

            baos.flush();
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
        return baos;
    }

    private String getStub(String type, ByteArrayOutputStream wsdlbaos, String uri)
            throws ScriptException , IOException {


        ByteArrayOutputStream stubOutStream = new ByteArrayOutputStream();
        InputStream wsdl20InputStream = null;
        String returnValue;
        try {
            OMElement documentElement = (OMElement) XMLUtils.toOM(new ByteArrayInputStream(wsdlbaos.toByteArray()));
            OMNamespace documentElementNS = documentElement.getNamespace();
            if (documentElementNS != null) {
                if (Constants.NS_URI_WSDL11.equals(documentElementNS.getNamespaceURI())) {
                    wsdl20InputStream = XSLTTransformer.getWSDL2(new ByteArrayInputStream(wsdlbaos.toByteArray()), null);
                } else if (WSDL2Constants.WSDL_NAMESPACE.equals(documentElementNS.getNamespaceURI())) {
                    wsdl20InputStream = new ByteArrayInputStream(wsdlbaos.toByteArray());
                } else {
                    throw new ScriptException("Invalid WSDL");
                }
            } else {
                throw new ScriptException("Invalid WSDL");
            }

            DOMSource sigStream = XSLTTransformer.getSigStream(wsdl20InputStream, null);
            Result result = new StreamResult(stubOutStream);
            Map<String, String> paramMap = null;
            if ("e4x".equals(type)) {
                paramMap = new HashMap<String, String>();
                paramMap.put("e4x", "true");
            }
            XSLTTransformer.generateStub(sigStream, result, paramMap);
            returnValue = stubOutStream.toString();
        } catch (XMLStreamException e) {
            throw new ScriptException(e);
        } catch (TransformerException e) {
            throw new ScriptException(e);
        } catch (ParserConfigurationException e) {
            throw new ScriptException(e);
        } finally {
            try {
                wsdl20InputStream.close();
                stubOutStream.close();
            } catch (IOException e) {
                log.error("Error while closing streams " + e.getMessage(), e);
                throw e;
            }
        }
        return returnValue;
    }
}
