package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.CertInfo;
import com.zetes.projects.bosa.signandvalidation.service.PdfVisibleSignatureService;
import com.zetes.projects.bosa.signandvalidation.service.RemoteXadesSignatureServiceImpl;
import com.zetes.projects.bosa.signandvalidation.service.StorageService;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signingconfigurator.service.SigningConfiguratorService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
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
import javax.servlet.http.HttpServletResponse;
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
import java.util.concurrent.TimeUnit;
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
    public static final String GET_DATA_TO_SIGN_FOR_TOKEN = "/getDataToSignForToken";
    public static final String GET_FILEINFO_FOR_TOKEN = "/getFileInfoForToken";
    public static final String GET_FILE_FOR_TOKEN = "/getFileForToken";
    public static final String SIGN_DOCUMENT_FOR_TOKEN = "/signDocumentForToken";

    public static final String GET_DATA_TO_SIGN = "/getDataToSign";
    public static final String SIGN_DOCUMENT = "/signDocument";

    public static final int TOKEN_VALIDITY_SECS = 5 * 60 * 60;
    private static final long SIGN_DURATION_SECS = 2 * 60;

    private static final String SYMETRIC_KEY_ALGO = "AES";

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

    // Secret key cache
    private static Cache<String, SecretKey> keyCache = CacheBuilder.newBuilder().expireAfterWrite(TOKEN_VALIDITY_SECS, TimeUnit.SECONDS).build();

    @PostMapping(value = FLOW_REST_RESOURCE, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String createSignFlow(@RequestBody CreateSignFlowDTO csf) {
        //TODO Validate all inputs ???
        // Check:
        // - if files are on the bucket
        // - XML -> XSLT coherence
        // - signTimeout boundaries ?
        // - nnAllowedToSign format adherence
        // - signProfile existence
        // - some policy checks..........
        // - Uniqueness of elementIds
        // - Filename collisions (inputs, out vs out, outxslt vs rest)

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
                file.setId(input.getXmlEltId());
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
                NodeList nodes = (NodeList)xPath.evaluate("//*[@id = '"+ input.getXmlEltId() + "']", doc, XPathConstants.NODESET);
                if (nodes.getLength() != 1) {
                    logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, "Can't find element id : " + input.getXmlEltId());
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

    @GetMapping(value = GET_FILE_FOR_TOKEN + "/{token}/{fileName}")
    public void getFileForToken(@PathVariable String token, @PathVariable String fileName, HttpServletResponse response) {
        InputStream file = null;
        try {
            CreateSignFlowDTO csf = extractToken(token);

            // Only allow downloads based on the token and the files listed in the token
            if (!isInputFile(csf, fileName)) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, INVALID_TOKEN, "File " + fileName + " not found in token");
            }
            FileStoreInfo fi = storageService.getFileInfo(csf.getBucket(), fileName);

            response.setContentType(fi.getContentType());
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Cache-Control", "no-cache");
            response.setHeader("Content-Transfer-Encoding", "binary");
            response.setHeader("Content-Disposition", fi.getContentType().equals(APPLICATION_PDF_VALUE) ? "inline" : "attachment" + "; filename=\"" + fileName + "\"");
            file = storageService.getFileAsStream(csf.getBucket(), fileName);
            Utils.copy(file, response.getOutputStream());
            file.close();
        } catch (IOException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            if (file != null) {
                try {
                    file.close();
                } catch (IOException e) { }
            }
        }
    }

    private boolean isInputFile(CreateSignFlowDTO csf, String fileName) {
        for(XmlSignInput input : csf.getInputs()) {
            if (fileName.equals(input.getFileName()) || fileName.equals(input.getDisplayXslt())) return true;
        }
        return false;
    }

    @PostMapping(value = GET_FILEINFO_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = TEXT_PLAIN_VALUE)
    public FileInfoForTokenDTO getFileInfoForToken(@RequestBody String token) {
        LOG.info("getFileInfoForToken");
        CreateSignFlowDTO csf = extractToken(token);

        FileInfoForTokenDTO fift = new FileInfoForTokenDTO();
        fift.setNnAllowedToSign(csf.getNnAllowedToSign());
        fift.setInputs(csf.getInputs());
        return fift;
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
            for(XmlSignInput input : csf.getInputs()) idsToSign.add(input.getXmlEltId());
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

            // TODO Moved the NN check to "sign" instead of "getDataForSign" ... Makes more security sense... But it would be nice to add a sign-gui check to warn user VERY early
            if (csf.getNnAllowedToSign() != null) {
                CertInfo certInfo = new CertInfo(clientSigParams.getSigningCertificate());
                String nn = certInfo.getSerialNumber();
                if (!csf.getNnAllowedToSign().contains(nn))
                {
                    logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, "NN not allowed to sign");
                }
            }

            long signTimeout = csf.getSignTimeout() != null ? csf.getSignTimeout() * 1000 : SIGN_DURATION_SECS * 1000;
            if (new Date().getTime() >= (clientSigParams.getSigningDate().getTime() + signTimeout)) {
                logAndThrowEx(BAD_REQUEST, SIGN_PERIOD_EXPIRED, "");
            }

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(csf.getSignProfile(), clientSigParams, csf.getPolicy());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());

            ArrayList<String> idsToSign = new ArrayList<String>(csf.getInputs().size());
            for(XmlSignInput input : csf.getInputs()) idsToSign.add(input.getXmlEltId());
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

    // Create a "token" based of n the CreateSignFlowDTO. This will be the driver for the whole process
    private String createToken(CreateSignFlowDTO csf)  {
        try {
            // JSONify & GZIP object
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            new ObjectMapper().writeValue(new GZIPOutputStream(bos), new SignFlowToken(csf));

            // Create new symetric Key
            KeyGenerator keygen = KeyGenerator.getInstance(SYMETRIC_KEY_ALGO);
            keygen.init(256);
            SecretKey newKey = keygen.generateKey();

            // Create new random KeyID
            byte[] kidBytes = new byte[9];
            new SecureRandom().nextBytes(kidBytes);
            String keyId = Base64.getUrlEncoder().encodeToString(kidBytes);
            // Store key in secret bucket
            storageService.storeFile(null, keyId, newKey.getEncoded());
            keyCache.put(keyId, newKey);

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

    // Extract and decrypt a "token"
    private CreateSignFlowDTO extractToken(String token) {
        try {
            JWEObject jweObject = JWEObject.parse(token);
            String keyId = jweObject.getHeader().getKeyID();
            SecretKey key = keyCache.getIfPresent(keyId);
            if (key == null) {
                byte rawKey[] = storageService.getFileAsBytes(null, keyId, false);
                key = new SecretKeySpec(rawKey, SYMETRIC_KEY_ALGO);
            }
            jweObject.decrypt(new DirectDecrypter(key));
            GZIPInputStream zis = new GZIPInputStream(new ByteArrayInputStream(jweObject.getPayload().toBytes()));
            SignFlowToken sft = new ObjectMapper().readValue(zis, SignFlowToken.class);
            if (!sft.isValid(TOKEN_VALIDITY_SECS)) {
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
