/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.jaggeryjs.modules.sso.common.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.IdResolver;
import org.jaggeryjs.modules.sso.common.constants.SSOConstants;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.StatusResponseTypeImpl;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class Util {

    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static boolean bootStrapped = false;
    private static final String ISSUER = "issuer";
    private static final String IDENTITY_PROVIDER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    private static final String NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
    private static final String TIME_STAMP_SKEW = "timeStampSkew";
    private static final int DEAFAULT_TIME_STAMP_SKEW_IN_SECONDS = 300;

    private static Random random = new Random();

    private static final char[] charMapping = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
            'p'};

    private static Log log = LogFactory.getLog(Util.class);

    /**
     * This method is used to initialize the OpenSAML2 library. It calls the bootstrap method, if it
     * is not initialized yet.
     */
    public static void doBootstrap() {
        if (!bootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                bootStrapped = true;
            } catch (ConfigurationException e) {
                System.err.println("Error in bootstrapping the OpenSAML2 library");
                e.printStackTrace();
            }
        }
    }

    public static XMLObject buildXMLObject(QName objectQName)
            throws Exception {

        XMLObjectBuilder builder = org.opensaml.xml.Configuration.getBuilderFactory().getBuilder(objectQName);
        if (builder == null) {
            throw new Exception("Unable to retrieve builder for object QName "
                    + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }


    /**
     * Generates a unique Id for Authentication Requests
     *
     * @return generated unique ID
     */
    public static String createID() {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            log.warn("Error while building Secure Random ID");
        }
        return null;
    }

    /**
     * Constructing the XMLObject Object from a String
     *
     * @param authReqStr
     * @return Corresponding XMLObject which is a SAML2 object
     * @throws Exception
     */
    public static XMLObject unmarshall(String authReqStr) throws Exception {
        XMLObject response;
        try {
            doBootstrap();
            DocumentBuilderFactory documentBuilderFactory = getSecuredDocumentBuilder();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(authReqStr.trim().getBytes()));
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            response = unmarshaller.unmarshall(element);
            NodeList list = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20P_NS, "Response");
            if (list.getLength() > 0) {
                log.error("Invalid schema for the SAML2 reponse. Multiple response objects found");
                throw new Exception("Error occured while processing saml2 response. Multiple response objects found");
            }
            NodeList assertionList = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS, "Assertion");
            if (response instanceof Assertion) {
                if (assertionList.getLength() > 0) {
                    log.error("Invalid schema for the SAML2 assertion. Multiple assertions detected");
                    throw new Exception("Error occurred while processing saml2 response. Multiple assertions detected");
                }
            } else {
                if (assertionList.getLength() > 1) {
                    log.error("Invalid schema for the SAML2 response. Multiple assertions detected");
                    throw new Exception("Error occurred while processing saml2 response. Multiple assertions detected");
                }
            }

            return response;
        } catch (Exception e) {
            throw new Exception("Error in constructing AuthRequest from " +
                    "the encoded String ", e);
        }
    }

    /**
     * Serializing a SAML2 object into a String
     *
     * @param xmlObject object that needs to serialized.
     * @return serialized object
     * @throws Exception
     */
    public static String marshall(XMLObject xmlObject) throws Exception {
        try {
            doBootstrap();
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl =
                    (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString();
        } catch (Exception e) {
            throw new Exception("Error Serializing the SAML Response", e);
        }
    }

    /**
     * Encoding the response
     *
     * @param xmlString
     *            String to be encoded
     * @return encoded String
     */
    public static String encode(String xmlString) {
        // Encoding the message
        String encodedRequestMessage =
                Base64.encodeBytes(xmlString.getBytes(),
                        Base64.DONT_BREAK_LINES);
        return encodedRequestMessage.trim();
    }

/*    *//**
     * Compressing and Encoding the response
     *
     * @param xmlString String to be encoded
     * @return compressed and encoded String
     *//*
    public static String encode(String xmlString) throws Exception {
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(
                byteArrayOutputStream, deflater);

        deflaterOutputStream.write(xmlString.getBytes());
        deflaterOutputStream.close();

        // Encoding the compressed message
        String encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream
                .toByteArray(), Base64.DONT_BREAK_LINES);
        return encodedRequestMessage.trim();
    }*/

    /**
     * Decoding and deflating the encoded AuthReq
     *
     * @param encodedStr encoded AuthReq
     * @return decoded AuthReq
     */

    public static String decode(String encodedStr) throws Exception {
        return new String(Base64.decode(encodedStr));
    }
    /*@Deprecated
    public static String decode(String encodedStr) throws Exception {
        try {
            org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            try {
                Inflater inflater = new Inflater(true);
                inflater.setInput(base64DecodedByteArray);
                byte[] xmlMessageBytes = new byte[5000];
                int resultLength = inflater.inflate(xmlMessageBytes);

                if (!inflater.finished()) {
                    throw new RuntimeException("didn't allocate enough space to hold "
                            + "decompressed data");
                }

                inflater.end();
                return new String(xmlMessageBytes, 0, resultLength, "UTF-8");

            } catch (DataFormatException e) {
                ByteArrayInputStream bais = new ByteArrayInputStream(
                        base64DecodedByteArray);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InflaterInputStream iis = new InflaterInputStream(bais);
                byte[] buf = new byte[1024];
                int count = iis.read(buf);
                while (count != -1) {
                    baos.write(buf, 0, count);
                    count = iis.read(buf);
                }
                iis.close();

                return new String(baos.toByteArray());
            }
        } catch (IOException e) {
            throw new Exception("Error when decoding the SAML Request.", e);
        }

    }*/


    /**
     * This method validates the signature of the SAML Response.
     *
     * @param resp SAML Response
     * @return true, if signature is valid.
     */
    public static boolean validateSignature(StatusResponseTypeImpl resp, String keyStoreName, String keyStorePassword,
            String alias, int tenantId, String tenantDomain) {
        if (resp.getSignature() == null) {
            log.error("SAML Response signing is enabled, but signature element not found in SAML Response element.");
            return false;
        }
        return validateSignature(resp.getSignature(), keyStoreName, keyStorePassword, alias, tenantId, tenantDomain);
    }

    public static boolean validateAssertionSignature(Response resp, String keyStoreName, String keyStorePassword,
            String alias, int tenantId, String tenantDomain) {
        Assertion assertion;
        assertion = retrieveAssertion(resp);
        if (assertion == null) {
            log.error("SAML Assertion not found in the Response");
            return false;
        }
        if (assertion.getSignature() == null) {
            log.error("SAMLAssertion signing is enabled, but signature element "
                    + "not found in SAML Assertion element.");
            return false;
        } else {
            return validateSignature(assertion.getSignature(), keyStoreName, keyStorePassword, alias, tenantId,
                    tenantDomain);
        }

    }

    private static boolean validateSignature(Signature signature, String keyStoreName, String keyStorePassword,
            String alias, int tenantId, String tenantDomain) {
        boolean isSigValid = false;
        try {
            KeyStore keyStore = null;
            java.security.cert.X509Certificate cert = null;
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                // get an instance of the corresponding Key Store Manager instance
                KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                cert = (java.security.cert.X509Certificate) keyStore.getCertificate(tenantDomain);
            } else {
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(new File(keyStoreName)), keyStorePassword.toCharArray());
                cert = (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
            }
            try {
                SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
                signatureProfileValidator.validate(signature);

                // Following code segment is taken from org.opensaml.security.SAMLSignatureProfileValidator
                // of OpenSAML 2.6.4. This is done to get the latest XSW related fixes.

                SignatureImpl sigImpl = (SignatureImpl) signature;
                XMLSignature apacheSig = sigImpl.getXMLSignature();
                SignableSAMLObject signableObject = (SignableSAMLObject) sigImpl.getParent();

                Reference ref = null;
                try {
                    ref = apacheSig.getSignedInfo().item(0);
                } catch (XMLSecurityException e) {
                    // This exception should never occur, because it's already checked
                    // from the previous call to signatureProfileValidator#validate
                    log.error("Apache XML Security exception obtaining Reference", e);
                    throw new ValidationException("Could not obtain Reference from Signature/SignedInfo", e);
                }

                String uri = ref.getURI();

                validateReferenceURI(uri, signableObject);
                validateObjectChildren(apacheSig);

                // End of OpenSAML 2.6.4 logic
            } catch (ValidationException e) {
                String logMsg = "Signature do not confirm to SAML signature profile. Possible XML Signature Wrapping "
                        + "Attack!";
                log.warn(logMsg);
                if (log.isDebugEnabled()) {
                    log.debug(logMsg, e);
                }
                return isSigValid;
            }

            X509CredentialImpl credentialImpl = new X509CredentialImpl(cert);
            SignatureValidator signatureValidator = new SignatureValidator(credentialImpl);
            signatureValidator.validate(signature);
            isSigValid = true;
            return isSigValid;
        } catch (Exception e) {
            log.error("Error while validating signature", e);
            return isSigValid;
        }
    }

    /**
     * Validates the 'Not Before' and 'Not On Or After' conditions of the SAML Assertion
     *
     * @param resp  SAML Response
     */
    public static boolean validateAssertionValidityPeriod(Response resp, Properties prop) {
        Assertion assertion;
        assertion = retrieveAssertion(resp);
        if (assertion == null) {
            log.error("SAML Assertion not found in the Response");
            return false;
        }
        DateTime validFrom = assertion.getConditions().getNotBefore();
        DateTime validTill = assertion.getConditions().getNotOnOrAfter();
        int timeStampSkewInSeconds = getTimeStampSkewInSeconds(prop);

        if (validFrom != null && validFrom.minusSeconds(timeStampSkewInSeconds).isAfterNow()) {
            log.error("Failed to meet SAML Assertion Condition 'Not Before'");
            return false;
        }

        if (validTill != null && validTill.plusSeconds(timeStampSkewInSeconds).isBeforeNow()) {
            log.error("Failed to meet SAML Assertion Condition 'Not On Or After'");
            return false;
        }

        if (validFrom != null && validTill != null && validFrom.isAfter(validTill)) {
            log.error("SAML Assertion Condition 'Not Before' must be less than the " + "value of 'Not On Or After'");
            return false;
        }
        return true;
    }

    /**
     * Validate the AudienceRestriction of SAML2 Response
     *
     * @param resp SAML response
     * @return validity
     */
    public static boolean validateAudienceRestriction(Response resp, Properties properties) {
        Assertion assertion;
        assertion = retrieveAssertion(resp);

        if (assertion == null) {
            log.error("SAML Assertion not found in the Response");
            return false;
        } else {
            Conditions conditions = assertion.getConditions();
            if (conditions != null) {
                List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
                if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                    for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                        if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                            boolean audienceFound = false;
                            for (Audience audience : audienceRestriction.getAudiences()) {
                                if (properties.get(ISSUER).equals(audience.getAudienceURI())) {
                                    audienceFound = true;
                                    break;
                                }
                            }
                            if (!audienceFound) {
                                log.error("SAML Assertion Audience Restriction validation failed");
                                return false;
                            }
                        } else {
                            log.error("SAML Response's AudienceRestriction doesn't contain Audiences");
                            return false;
                        }
                    }
                } else {
                    log.error("SAML Response doesn't contain AudienceRestrictions");
                    return false;
                }
            } else {
                log.error("SAML Response doesn't contain Conditions");
                return false;
            }
        }
        return true;
    }

    private static int getTimeStampSkewInSeconds(Properties prop) {
        int timeStampSkewInSeconds = DEAFAULT_TIME_STAMP_SKEW_IN_SECONDS;
        if (prop != null && prop.containsKey(TIME_STAMP_SKEW)) {
            String timeStampSkew = prop.get(TIME_STAMP_SKEW).toString();
            if (timeStampSkew != null && timeStampSkew.length() > 0) {
                timeStampSkewInSeconds = Integer.parseInt(timeStampSkew);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("TimestampSkew is set to " + timeStampSkewInSeconds + " s.");
        }

        return timeStampSkewInSeconds;
    }


    private static Assertion retrieveAssertion(Response resp) {
        Assertion assertion = null;
        List<Assertion> assertions = resp.getAssertions();
        if (CollectionUtils.isNotEmpty(assertions)) {
            if (assertions.size() != 1) {
                log.error("SAML Response contains multiple assertions");
                return assertion;
            }
            assertion = assertions.get(0);
        }
        return assertion;
    }

    public static String getDomainName(XMLObject samlObject) {
        NodeList list = samlObject.getDOM().getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
        String domainName = null;
        if (list.getLength() > 0) {
            String userName = list.item(0).getTextContent();
            domainName = MultitenantUtils.getTenantDomain(userName);
        }
        return domainName;
    }

    /**
     * Generate the key store name from the domain name
     *
     * @param tenantDomain tenant domain name
     * @return key store file name
     */
    private static String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(".", "-");
        return (ksName + ".jks");
    }

    /**
     * Create DocumentBuilderFactory with the XXE prevention measurements
     *
     * @return DocumentBuilderFactory instance
     */
    public static DocumentBuilderFactory getSecuredDocumentBuilder() {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE, false);
        } catch (ParserConfigurationException e) {
            log.error(
                    "Failed to load XML Processor Feature " + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE + " or " +
                            Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE + " or " + Constants.LOAD_EXTERNAL_DTD_FEATURE);
        }

        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        dbf.setAttribute(Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY, securityManager);

        return dbf;
    }
    
    /** Build NameIDPolicy object given name ID policy format
    *
    * @param nameIdPolicy Name ID policy format
    * @return SAML NameIDPolicy object
    */
   public static NameIDPolicy buildNameIDPolicy(String nameIdPolicy) {
       NameIDPolicy nameIDPolicyObj = new NameIDPolicyBuilder().buildObject();
       if (!StringUtils.isEmpty(nameIdPolicy)) {
           nameIDPolicyObj.setFormat(nameIdPolicy);
       } else {
           nameIDPolicyObj.setFormat(SSOConstants.NAME_ID_POLICY_DEFAULT);
       }
       nameIDPolicyObj.setAllowCreate(true);
       return nameIDPolicyObj;
   }
	
    /** Build NameID object given name ID format
    *
    * @param nameIdFormat Name ID format
    * @param subject Subject
    * @return SAML NameID object
    */
   public static NameID buildNameID(String nameIdFormat, String subject) {
       NameID nameIdObj = new NameIDBuilder().buildObject();
       if (!StringUtils.isEmpty(nameIdFormat)) {
           nameIdObj.setFormat(nameIdFormat);
       } else {
           nameIdObj.setFormat(SSOConstants.NAME_ID_POLICY_DEFAULT);
       }
       nameIdObj.setValue(subject);
       return nameIdObj;
   }
   
   /**
    * Replaces the ${} in url with system properties and returns
    *
    * @param acsUrl assertion consumer service url
    * @return acsUrl with system properties replaced
    */
   public static String processAcsUrl(String acsUrl) {
       //matches shortest segments that are between '{' and '}'
       Pattern pattern = Pattern.compile("\\$\\{(.*?)\\}");
       Matcher matcher = pattern.matcher(acsUrl);
       while (matcher.find()) {
           String match = matcher.group(1);
           String property = System.getProperty(match);
           if (property != null) {
               acsUrl = acsUrl.replace("${" + match + "}", property);
           } else {
               log.warn("System Property " + match + " is not set");
           }
       }
       return acsUrl;
   }

    /**
     * Validate the Signature's Reference URI.
     *
     * First validate the Reference URI against the parent's ID itself.  Then validate that the
     * URI (if non-empty) resolves to the same Element node as is cached by the SignableSAMLObject.
     *
     *
     * @param uri the Signature Reference URI attribute value
     * @param signableObject the SignableSAMLObject whose signature is being validated
     * @throws ValidationException  if the URI is invalid or doesn't resolve to the expected DOM node
     */
    private static void validateReferenceURI(String uri, SignableSAMLObject signableObject) throws ValidationException {
        if (DatatypeHelper.isEmpty(uri)) {
            return;
        }

        String uriID = uri.substring(1);

        Element expected = signableObject.getDOM();
        if (expected == null) {
            log.error("SignableSAMLObject does not have a cached DOM Element.");
            throw new ValidationException("SignableSAMLObject does not have a cached DOM Element.");
        }
        Document doc = expected.getOwnerDocument();

        Element resolved = IdResolver.getElementById(doc, uriID);
        if (resolved == null) {
            log.error("Apache xmlsec IdResolver could not resolve the Element for id reference: " + uriID);
            throw new ValidationException(
                    "Apache xmlsec IdResolver could not resolve the Element for id reference: " + uriID);
        }

        if (!expected.isSameNode(resolved)) {
            log.error("Signature Reference URI " + uri + " did not resolve to the expected parent Element");
            throw new ValidationException("Signature Reference URI did not resolve to the expected parent Element");
        }
    }

    /**
     * Validate that the Signature instance does not contain any ds:Object children.
     *
     * @param apacheSig the Apache XML Signature instance
     * @throws ValidationException if the signature contains ds:Object children
     */
    private static void validateObjectChildren(XMLSignature apacheSig) throws ValidationException {
        if (apacheSig.getObjectLength() > 0) {
            log.error("Signature contained " + apacheSig.getObjectLength() + " ds:Object child element(s)");
            throw new ValidationException("Signature contained illegal ds:Object children");
        }
    }


}
