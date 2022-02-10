package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.PdfVisibleSignatureService;
import com.zetes.projects.bosa.signandvalidation.service.RemoteXadesSignatureServiceImpl;
import com.zetes.projects.bosa.signandvalidation.service.StorageService;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.service.SigningConfiguratorService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.*;

@RestController
@RequestMapping(value = XMLSigningController.ENDPOINT)
public class XMLSigningController extends ControllerBase implements ErrorStrings {

    private static final Logger LOG = LoggerFactory.getLogger(XMLSigningController.class);

    public static final String ENDPOINT = "/sign";
    public static final String PING = "/ping";
    public static final String FLOW_REST_RESOURCE = "/flow";
    public static final String GET_DATA_TO_SIGN = "/getDataToSign";
    public static final String GET_DATA_TO_SIGN_FOR_TOKEN = "/getDataToSignForToken";
    public static final String SIGN_DOCUMENT = "/signDocument";
    public static final String SIGN_DOCUMENT_FOR_TOKEN = "/signDocumentForToken";

    private static final String SYMECTRIC_KEY_ALGO = "AES";

    @Autowired
    private SigningConfiguratorService signingConfigService;

    @Autowired
    private RemoteXadesSignatureServiceImpl altSignatureService;

    @Autowired
    private StorageService storageService;

    @GetMapping(value = PING, produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = FLOW_REST_RESOURCE, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String createSignFlow(@RequestBody CreateSignFlowDTO csf) {
        // Validate input
        if(!(storageService.isValidAuth(csf.getBucket(), csf.getPassword()))) {
            logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
        }
        // Clear unneeded fields
        csf.setPassword(null);

        createSignedFile(csf);

        // Create Token
        return createToken(csf);
    }

    private void createSignedFile(CreateSignFlowDTO csf) {
        try {
            LOG.info("Creating xml file");

            // Create BOSA XML Template
            XadesFileRoot root = new XadesFileRoot();
            for(XmlSignInput input : csf.getInputs()) {
                XadesFile file = new XadesFile();
                file.setName(input.getFileName());
                file.setId(input.getTargetXmlEltId());
                root.getFiles().add(file);
            }
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            JAXBContext context = JAXBContext.newInstance(XadesFileRoot.class);

            Document doc = dbf.newDocumentBuilder().newDocument();
            context.createMarshaller().marshal(root, doc);

            if (LOG.isDebugEnabled()) {
                LOG.debug(xmlDocToString(doc));
            }

            TransformerFactory tf = TransformerFactory.newInstance();
            // If requested create target file
            String xslt = csf.getOutXslt();
            if (xslt != null) {
                // XSLT present -> transform to proprietary format
                DOMResult xsltDom = new DOMResult();
                InputStream xsltStream = storageService.getFileAsStream(csf.getBucket(), xslt);
                tf.newTransformer(new StreamSource(xsltStream)).transform(new DOMSource(doc), xsltDom);
                doc = (Document)xsltDom.getNode();

                if (LOG.isDebugEnabled()) {
                    LOG.debug(xmlDocToString(doc));
                }
            }

            // Put file content in the target document
            XPath xPath = XPathFactory.newInstance().newXPath();
            for(XmlSignInput input : csf.getInputs()) {
                NodeList nodes = (NodeList)xPath.evaluate("//*[@id = '"+ input.getTargetXmlEltId() + "']", doc, XPathConstants.NODESET);
                if (nodes.getLength() != 1) {
                    logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, "Can't find element id : " + input.getTargetXmlEltId());
                }
                nodes.item(0).setTextContent(storageService.getFileAsB64String(csf.getBucket(), input.getFileName()));
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug(xmlDocToString(doc));
            }

            // Save target XML to bucket
            ByteArrayOutputStream outStream = new ByteArrayOutputStream(32768);
            tf.newTransformer().transform(new DOMSource(doc), new StreamResult(outStream));
            storageService.storeFile(csf.getBucket(), csf.getOutFileName(), outStream.toByteArray());

            LOG.info("Done creating xml file");

        } catch (JAXBException | TransformerException | XPathExpressionException | ParserConfigurationException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
    }

    @PostMapping(value = GET_DATA_TO_SIGN_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        try {
            LOG.info("getDataToSignForToken");
            CreateSignFlowDTO csf = extractToken(dataToSignForTokenDto.getToken());

            ClientSignatureParameters clientSigParams = dataToSignForTokenDto.getClientSignatureParameters();
            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(csf.getSignProfile(), clientSigParams, csf.getPolicy());

            ArrayList<String> idsToSign = new ArrayList<String>(csf.getInputs().size());
            for(XmlSignInput input : csf.getInputs()) idsToSign.add(input.getTargetXmlEltId());
            List<DSSReference> references = buildReferences(signingDate, idsToSign, parameters.getReferenceDigestAlgorithm());

            byte[] bytesToSign = storageService.getFileAsBytes(csf.getBucket(), csf.getOutFileName(), true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, csf.getOutFileName());
            ToBeSignedDTO dataToSign = altSignatureService.getDataToSignWithReferences(fileToSign, parameters, references);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO dts = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), signingDate);
            LOG.info("done getDataToSignForToken");
            return dts;

        } catch (NullParameterException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = SIGN_DOCUMENT_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDto) {
        try {
            LOG.info("signDocumentForToken");
            CreateSignFlowDTO csf = extractToken(signDto.getToken());

            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(csf.getSignProfile(), clientSigParams, csf.getPolicy());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());

            ArrayList<String> idsToSign = new ArrayList<String>(csf.getInputs().size());
            for(XmlSignInput input : csf.getInputs()) idsToSign.add(input.getTargetXmlEltId());
            List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), idsToSign, parameters.getReferenceDigestAlgorithm());

            byte[] bytesToSign = storageService.getFileAsBytes(csf.getBucket(), csf.getOutFileName(), true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, csf.getOutFileName());
            RemoteDocument signedDoc = altSignatureService.signDocumentWithReferences(fileToSign, parameters, signatureValueDto, references);

            storageService.storeFile(csf.getBucket(), csf.getOutFileName(), signedDoc.getBytes());
            signedDoc.setName(csf.getOutFileName());
            LOG.info("done signDocumentForToken");
            return signedDoc;
        } catch (IOException | NullParameterException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    private String createToken(CreateSignFlowDTO csf)  {
        try {
            // JSONify & GZIP object
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            new ObjectMapper().writeValue(new GZIPOutputStream(bos), new SignFlowToken(csf));

            // Create new symetric Key
            KeyGenerator keygen = KeyGenerator.getInstance(SYMECTRIC_KEY_ALGO);
            keygen.init(256);
            SecretKey newKey = keygen.generateKey();

            // Create new random KeyID
            byte[] kidBytes = new byte[9];
            new SecureRandom().nextBytes(kidBytes);
            String keyId = Base64.getUrlEncoder().encodeToString(kidBytes);
            // Store key in secret bucket
            storageService.storeFile(null, keyId, newKey.getEncoded());

            // Pack all into a JWE & Encrypt
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                    .keyID(keyId)
                    .build(), new Payload(bos.toByteArray()));
            jweObject.encrypt(new DirectEncrypter(newKey));
            return jweObject.serialize();
        } catch (IOException | NoSuchAlgorithmException | JOSEException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null;
    }

    private CreateSignFlowDTO extractToken(String token) {
        try {
            JWEObject jweObject = JWEObject.parse(token);
            byte rawKey[] = storageService.getFileAsBytes(null, jweObject.getHeader().getKeyID(), false);
            jweObject.decrypt(new DirectDecrypter(new SecretKeySpec(rawKey, SYMECTRIC_KEY_ALGO)));
            GZIPInputStream zis = new GZIPInputStream(new ByteArrayInputStream(jweObject.getPayload().toBytes()));
            SignFlowToken sft = new ObjectMapper().readValue(zis, SignFlowToken.class);
            if (!sft.isValid(5 * 60 )) {
                logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, "Token is expired");
            }
            return sft.getCsf();
        } catch(ParseException | IOException | JOSEException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, e);
        }
        return  null;
    }

    @PostMapping(value = GET_DATA_TO_SIGN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignXMLElementsDTO getDataToSignDto) {
        try {
            ClientSignatureParameters clientSigParams = getDataToSignDto.getClientSignatureParameters();
            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(getDataToSignDto.getSigningProfileId(), clientSigParams, getDataToSignDto.getPolicy());

            List<DSSReference> references = buildReferences(signingDate, getIdsToSign(getDataToSignDto.getElementsToSign()), parameters.getReferenceDigestAlgorithm());
            ToBeSignedDTO dataToSign = altSignatureService.getDataToSignWithReferences(getDataToSignDto.getToSignDocument(), parameters, references);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), signingDate);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = SIGN_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignXMLElementsDTO signDto) {
        try {
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDto.getSigningProfileId(), clientSigParams, signDto.getPolicy());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());
            List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), getIdsToSign(signDto.getElementsToSign()), parameters.getReferenceDigestAlgorithm());
            RemoteDocument signedDoc = altSignatureService.signDocumentWithReferences(signDto.getToSignDocument(), parameters, signatureValueDto, references);

            signedDoc.setName(signDto.getToSignDocument().getName());
            return signedDoc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // We won't get here
    }

    private List<String> getIdsToSign(List<SignElement> elementsToSign) {
        ArrayList<String> list = new ArrayList<String>(elementsToSign.size());
        for(SignElement elementToSign : elementsToSign) list.add(elementToSign.getId());
        return list;
    }

    private List<DSSReference> buildReferences(Date signingTime, List<String> xmlIds, DigestAlgorithm refDigestAlgo) {
        String timeRef = Long.toString(signingTime.getTime());
        List<DSSReference> references = new ArrayList<DSSReference>();
        int count = 0;
        for(String xmlId : xmlIds) {
            DSSReference reference = new DSSReference();
            reference.setId(timeRef + "-" + Integer.toString(count++));
            reference.setDigestMethodAlgorithm(refDigestAlgo == null ? DigestAlgorithm.SHA256 : refDigestAlgo);
            reference.setUri("#"+ xmlId);
            List<DSSTransform> transforms = new ArrayList<>();
            CanonicalizationTransform transform = new CanonicalizationTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            transforms.add(transform);
            reference.setTransforms(transforms);
            references.add(reference);
        }
        return references;
    }

    private String xmlDocToString(Document doc) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.getBuffer().toString();
    }
}
