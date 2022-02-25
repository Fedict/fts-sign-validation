package com.zetes.projects.bosa.signandvalidation.controller;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.zetes.projects.bosa.signandvalidation.service.*;
import com.zetes.projects.bosa.signandvalidation.utils.MediaTypeUtil;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.PdfVisibleSignatureService.PdfVisibleSignatureException;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import com.zetes.projects.bosa.signingconfigurator.service.SigningConfiguratorService;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteMultipleDocumentsSignatureService;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import eu.europa.esig.dss.enumerations.Indication;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.springframework.http.HttpStatus;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.*;

import org.springframework.http.ResponseEntity;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

@RestController
@RequestMapping(value = SigningController.ENDPOINT)
public class SigningController extends ControllerBase implements ErrorStrings {

    private static final Logger LOG = LoggerFactory.getLogger(SigningController.class);

    // Service URL
    public static final String ENDPOINT                         = "/signing";

    public static final String PING                             = "/ping";
    // Token operations
    public static final String GET_TOKEN_FOR_DOCUMENT           = "/getTokenForDocument";
    public static final String GET_TOKEN_FOR_DOCUMENTS          = "/getTokenForDocuments";
    public static final String GET_DATA_TO_SIGN_FOR_TOKEN       = "/getDataToSignForToken";
    public static final String GET_METADATA_FOR_TOKEN           = "/getMetadataForToken";
    public static final String GET_DOCUMENT_FOR_TOKEN           = "/getDocumentForToken";
    public static final String GET_FILE_FOR_TOKEN               = "/getFileForToken";
    public static final String SIGN_DOCUMENT_FOR_TOKEN          = "/signDocumentForToken";

    public static final int TOKEN_VALIDITY_SECS                 = 5 * 60 * 60;
    private static final long SIGN_DURATION_SECS                = 2 * 60;
    private static final int MAX_NN_ALLOWED_TO_SIGN             = 32;
    private static final Pattern nnPattern                      = Pattern.compile("[0-9]{11}");
    private static final Pattern eltIdPattern                   = Pattern.compile("[a-zA-Z0-9\\-_]{1,30}");

    private static final List<String> allowedLanguages          =  Arrays.asList(new String[] {"fr", "ge", "nl", "en" });

    // standard operations
    public static final String GET_DATA_TO_SIGN                 = "/getDataToSign";
    public static final String SIGN_DOCUMENT                    = "/signDocument";
    public static final String EXTEND_DOCUMENT                  = "/extendDocument";
    public static final String EXTEND_DOCUMENT_MULTIPLE         = "/extendDocumentMultiple";
    public static final String TIMESTAMP_DOCUMENT               = "/timestampDocument";
    public static final String TIMESTAMP_DOCUMENT_MULTIPLE      = "/timestampDocumentMultiple";
    public static final String GET_DATA_TO_SIGN_XADES_MULTI_DOC = "/getDataToSignXades";
    public static final String SIGN_DOCUMENT_XADES_MULTI_DOC    = "/signDocumentXades";

    private static final String KEYS_FOLDER                     = "keys/";
    private static final String SYMMETRIC_KEY_ALGO              = "AES";

    private static final SimpleDateFormat logDateTimeFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
    private static final SimpleDateFormat reportDateTimeFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    // Secret key cache
    private static Cache<String, SecretKey> keyCache = CacheBuilder.newBuilder().expireAfterWrite(TOKEN_VALIDITY_SECS, TimeUnit.SECONDS).build();

    @Autowired
    private SigningConfiguratorService signingConfigService;

    @Autowired
    private PdfVisibleSignatureService pdfVisibleSignatureService;

    @Autowired
    private RemoteMultipleDocumentsSignatureService signatureServiceMultiple;

    @Autowired
    private BosaRemoteDocumentValidationService validationService;

    @Autowired
    private ReportsService reportsService;
    
    @Autowired
    private RemoteXadesSignatureServiceImpl altSignatureService;

    @Autowired
    private StorageService storageService;

    @GetMapping(value = PING, produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    /*****************************************************************************************
     *
     * TOKEN Signing services
     *
     ****************************************************************************************/

    @PostMapping(value = GET_TOKEN_FOR_DOCUMENT, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocument(@RequestBody GetTokenForDocumentDTO tokenData) {
        try {
            if(!(storageService.isValidAuth(tokenData.getName(), tokenData.getPwd()))) {
                logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
            }

            List<TokenSignInput> inputs = new ArrayList<>();
            TokenSignInput input = new TokenSignInput();
            input.setFileName(tokenData.getIn());
            input.setReadConfirm(tokenData.isRequestDocumentReadConfirm());
            input.setDisplay(DisplayType.Content);
            input.setSignLanguage(tokenData.getLang());
            input.setPspFileName(tokenData.getPsp());
            input.setPsfP(tokenData.getPsfP() == null ? false : "true".compareTo(tokenData.getPsfP()) == 0);
            input.setPsfC(tokenData.getPsfC());
            input.setPsfN(tokenData.getPsfN());
            input.setDisplayXslt(tokenData.getXslt());
            inputs.add(input);
            TokenObject token = new TokenObject(false, tokenData.getName(), tokenData.getProf(), inputs, tokenData.getOut());
            if (tokenData.getPolicyId() != null) {
                token.setPolicy(new PolicyParameters(tokenData.getPolicyId(), tokenData.getPolicyDescription(), DigestAlgorithm.valueOf(tokenData.getPolicyDigestAlgorithm())));
            }
            token.setOutDownload(!tokenData.isNoDownload());
            token.setSignTimeout(tokenData.getSignTimeout());
            if (tokenData.getAllowedToSign() != null) {
                List<String> nnAllowedToSign = new ArrayList<>();
                for(AllowedToSign allowedToSign : tokenData.getAllowedToSign()) {
                    nnAllowedToSign.add(allowedToSign.getNN());
                }
                token.setNnAllowedToSign(nnAllowedToSign);
            }

            checkToken(token);

            return createToken(token);
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = GET_TOKEN_FOR_DOCUMENTS, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocuments(@RequestBody GetTokenForDocumentsDTO gtfd) {
        // Validate input
        if(!(storageService.isValidAuth(gtfd.getBucket(), gtfd.getPassword()))) {
            logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
        }

        TokenObject token = new TokenObject();
        token.setXadesMultifile(true);
        token.setBucket(gtfd.getBucket());
        token.setSignTimeout(gtfd.getSignTimeout());
        token.setNnAllowedToSign(gtfd.getNnAllowedToSign());
        token.setSignProfile(gtfd.getSignProfile());
        PolicyDTO policy = gtfd.getPolicy();
        if (policy != null) {
            token.setPolicy(new PolicyParameters(policy.getId(), policy.getDescription(), policy.getDigestAlgorithm()));
        }
        List<TokenSignInput> tokenInputs = new ArrayList<>();
        for(SignInput input : gtfd.getInputs()) {
            TokenSignInput ti = new TokenSignInput();
            ti.setFileName(input.getFileName());
            ti.setXmlEltId(input.getXmlEltId());
            ti.setReadConfirm(input.isReadConfirm());
            ti.setDisplay(input.getDisplay());
            ti.setDisplayXslt(input.getDisplayXslt());
            tokenInputs.add(ti);
        }
        token.setInputs(tokenInputs);
        token.setOutXslt(gtfd.getOutXslt());
        token.setOutFileName(gtfd.getOutFileName());
        token.setOutDownload(gtfd.isOutDownload());

        checkToken(token);

        createSignedFile(token);

        // Create Token
        return createToken(token);
    }

    private void checkToken(TokenObject token) {

        if (token.getSignProfile() == null) {
            //TODO Validate signProfile further
            logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "signProfile is null." , null);
        }

        PolicyParameters policy = token.getPolicy();
        if (policy != null) {
            if (policy.getPolicyId() == null) {
                logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "policyId is null." , null);
            }
            if (policy.getPolicyDigestAlgorithm() == null) {
                policy.setPolicyDigestAlgorithm(DigestAlgorithm.SHA256);
            }
            // TODO more policy checks ?
        }

        if (token.getSignTimeout() != null && token.getSignTimeout() > TOKEN_VALIDITY_SECS) {
            logAndThrowEx(FORBIDDEN, SIGN_PERIOD_EXPIRED, "signTimeout (" + token.getSignTimeout() + ") can't be larger than TOKEN_VALIDITY_SECS (" + TOKEN_VALIDITY_SECS + ")" , null);
        }
        List<String> nnsAllowedToSign = token.getNnAllowedToSign();
        if (nnsAllowedToSign != null) {
            if (nnsAllowedToSign.size() > MAX_NN_ALLOWED_TO_SIGN) {
                logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "nnAllowedToSign (" + nnsAllowedToSign.size() + ") can't be larger than MAX_NN_ALLOWED_TO_SIGN (" + MAX_NN_ALLOWED_TO_SIGN + ")" , null);
            }
            List<String> nnList = new ArrayList<String>();
            for(String nnAllowedToSign : nnsAllowedToSign) {
                checkValue("nnAllowedToSign", nnAllowedToSign, false, nnPattern, nnList);
            }
        }

        List<TokenSignInput> inputs = token.getInputs();
        if (inputs.size() == 0) {
            logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'inputs' field is empty" , null);
        }
        List<String> filenamesList = new ArrayList<String>();
        List<String> eltIdList = new ArrayList<String>();
        for(TokenSignInput input : inputs) {
            MediaType inputFileType = MediaTypeUtil.getMediaTypeFromFilename(input.getFileName());
            if (token.isXadesMultifile()) {
                checkValue("XmlEltId", input.getXmlEltId(), false, eltIdPattern, eltIdList);
                if (input.getPsfN() != null || input.getPsfC() != null || input.getSignLanguage() != null || input.getPspFileName() != null) {
                    logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null", null);
                }
            } else {
                if (input.getXmlEltId() != null) {
                    logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'XmlEltId' must be null", null);
                }
                if (APPLICATION_PDF.equals(inputFileType)) {
                    String signLanguage = input.getSignLanguage();
                    if (signLanguage != null && !allowedLanguages.contains(signLanguage)) {
                        logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'SignLanguage' (" + signLanguage + ") must be one of " + String.join(", ", allowedLanguages), null);
                    }
                    // TODO Validate  PSFxxx, psp, ... fields
                }
            }
            if (!APPLICATION_XML.equals(inputFileType) && input.getDisplayXslt() != null) {
                logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "DisplayXslt must be null", null);
            }
            checkValue("fileName", input.getFileName(), false, null, filenamesList);
        }

        if (token.getOutXslt() != null) {
            if (token.isXadesMultifile()) {
                checkValue("OutXslt", token.getOutXslt(), true, null, filenamesList);
            } else {
                logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'OutXslt' must be null", null);
            }
        }
        checkValue("outFileName", token.getOutFileName(), false, null, filenamesList);
    }

    private void checkValue(String name, String value, boolean nullable, Pattern patternToMatch, List<String> uniqueList) {
        if (value != null) {
            if (uniqueList != null) {
                if (uniqueList.contains(value)) {
                    logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'" + name + "' (" + value + ") is not unique", null);
                }
                uniqueList.add(value);
            }
            if (patternToMatch != null) {
                if (!patternToMatch.matcher(value).matches()) {
                    logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'" + name + "' (" + value + ") does not math Regex (" + patternToMatch.pattern() + ")" , null);
                }
            }
        } else {
            if (!nullable) {
                logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'" + name + "' is NULL", null);
            }
        }
    }

    private void createSignedFile(TokenObject token) {
        try {
            LOG.info("Creating xml file");

            // Create BOSA XML Template
            XadesFileRoot root = new XadesFileRoot();
            for(TokenSignInput input : token.getInputs()) {
                XadesFile file = new XadesFile();
                file.setName(input.getFileName());
                file.setId(input.getXmlEltId());
                file.setSize(storageService.getFileInfo(token.getBucket(), input.getFileName()).getSize());
                root.getFiles().add(file);
            }
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            JAXBContext context = JAXBContext.newInstance(XadesFileRoot.class);

            Document doc = dbf.newDocumentBuilder().newDocument();
            context.createMarshaller().marshal(root, doc);

            if (LOG.isInfoEnabled()) {
                LOG.info(xmlDocToString(doc));
            }

            TransformerFactory tf = new net.sf.saxon.BasicTransformerFactory();
            // If requested create target file
            String xslt = token.getOutXslt();
            if (xslt != null) {
                // XSLT present -> transform to proprietary format
                DOMResult xsltDom = new DOMResult();
                InputStream xsltStream = storageService.getFileAsStream(token.getBucket(), xslt);
                tf.newTransformer(new StreamSource(xsltStream)).transform(new DOMSource(doc), xsltDom);
                doc = (Document)xsltDom.getNode();

                if (LOG.isInfoEnabled()) {
                    LOG.info(xmlDocToString(doc));
                }
            }

            putFilesContent(doc.getFirstChild(), token);

            if (LOG.isInfoEnabled()) {
                LOG.info(xmlDocToString(doc));
            }

            // Save target XML to bucket
            ByteArrayOutputStream outStream = new ByteArrayOutputStream(32768);
            tf.newTransformer().transform(new DOMSource(doc), new StreamResult(outStream));
            storageService.storeFile(token.getBucket(), token.getOutFileName(), outStream.toByteArray());

            LOG.info("Done creating xml file");

        } catch (JAXBException | TransformerException | ParserConfigurationException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
    }

    private void putFilesContent(Node node, TokenObject token) throws StorageService.InvalidKeyConfigException {
        while(node != null) {
            putFilesContent(node.getFirstChild(), token);
            if (node.getAttributes() != null) {
                // Use DSS libraries to identify ID XML attributes
                String id = DSSXMLUtils.getIDIdentifier(node);
                if (id != null) {
                    for (TokenSignInput input : token.getInputs()) {
                        if (id.compareTo(input.getXmlEltId()) == 0) {
                            node.setTextContent(storageService.getFileAsB64String(token.getBucket(), input.getFileName()));
                            break;
                        }
                    }
                }
            }
            node = node.getNextSibling();
        }
    }

    @GetMapping(value = GET_METADATA_FOR_TOKEN)
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String tokenString) {
            logger.info("Entering getMetadataForToken()");
            try {
                TokenObject token = extractToken(tokenString);
                List<SignInputMetadata> signedInputsMetadata = new ArrayList<>();
                for(TokenSignInput input : token.getInputs()) {
                    SignInputMetadata inputMetadata = new SignInputMetadata();
                    inputMetadata.setFileName(input.getFileName());
                    inputMetadata.setMimeType(MediaTypeUtil.getMediaTypeFromFilename(input.getFileName()).toString());
                    inputMetadata.setDisplay(input.getDisplay());
                    inputMetadata.setDisplayXslt(input.getDisplayXslt());
                    inputMetadata.setReadConfirm(input.isReadConfirm());
                    signedInputsMetadata.add(inputMetadata);
                }
                SignInputMetadata fi = signedInputsMetadata.get(0);

                String xsltUrl = null;
                if(fi.getDisplayXslt() != null) {
                    xsltUrl = "${BEurl}/signing/getDocumentForToken?type=xslt&token=" + tokenString;
                }
                return new DocumentMetadataDTO(fi.getFileName(), fi.getMimeType(), xsltUrl, token.getInputs().get(0).isPsfP(), !token.isOutDownload(), fi.isReadConfirm(), signedInputsMetadata);

            } catch (RuntimeException e){
                    logAndThrowEx(tokenString, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
            }
            return null; // We won't get here
    }

    @GetMapping(value = GET_DOCUMENT_FOR_TOKEN)
    public void getDocumentForToken(@RequestParam("token") String tokenString, @RequestParam(required = false) String type, HttpServletResponse response) {
        logger.info("Entering getDocumentForToken()");

        TokenObject token = extractToken(tokenString);
        if (token.isXadesMultifile()) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INVALID_TOKEN, "Please call " + GET_FILE_FOR_TOKEN);
        }

        TokenSignInput firstInput = token.getInputs().get(0);
        String fileName = firstInput.getFileName();
        if (type != null) {
            if (!"xslt".equals(type)) {
                logAndThrowEx(tokenString, BAD_REQUEST, INVALID_TYPE, null, null);
            }
            fileName = firstInput.getDisplayXslt();
        }

       returnFile(token.getBucket(), fileName, response);
    }

    @GetMapping(value = GET_FILE_FOR_TOKEN + "/{token}/{type}/{inputIndex}")
    public void getFileForToken(@PathVariable("token") String tokenString, @PathVariable String type, @PathVariable Integer inputIndex, HttpServletResponse response) {
        TokenObject token = extractToken(tokenString);

        String fileName = null;
        if (inputIndex != null) {
            TokenSignInput input = token.getInputs().get(inputIndex);
            switch(type) {
                case "doc":
                    fileName = input.getFileName();
                    break;
                case "psp":
                    fileName = input.getPspFileName();
                    break;
                case "xslt":
                    fileName = input.getDisplayXslt();
                    break;
            }
        } else {
            fileName = token.getOutXslt();
        }
        returnFile(token.getBucket(), fileName, response);
    }

    private void returnFile(String bucket, String fileName, HttpServletResponse response) {
        logger.info("Entering returnFile()");
        InputStream file = null;
        try {
            FileStoreInfo fi = storageService.getFileInfo(bucket, fileName);

            response.setContentType(fi.getContentType().toString());
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Cache-Control", "no-cache");
            response.setHeader("Content-Transfer-Encoding", "binary");
            response.setHeader("Content-Disposition", fi.getContentType().equals(APPLICATION_PDF) ? "inline" : "attachment" + "; filename=\"" + fileName + "\"");
            file = storageService.getFileAsStream(bucket, fileName);
            Utils.copy(file, response.getOutputStream());
            file.close();
            logger.info("Leaving returnFile()");
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

    @PostMapping(value = GET_DATA_TO_SIGN_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        logger.info("Entering getDataToSignForToken()");
        try {
            TokenObject token = extractToken(dataToSignForTokenDto.getToken());
            ClientSignatureParameters clientSigParams = dataToSignForTokenDto.getClientSignatureParameters();

            // Signer allowed to sign ?
            checkNNAllowedToSign(token.getNnAllowedToSign(), clientSigParams.getSigningCertificate());

            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(token.getSignProfile(), clientSigParams, token.getPolicy());

            String fileName;
            List<DSSReference> references = null;
            TokenSignInput firstInput = token.getInputs().get(0);
            if (token.isXadesMultifile()) {
                List<String> idsToSign = new ArrayList<String>(token.getInputs().size());
                for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
                references = buildReferences(signingDate, idsToSign, parameters.getReferenceDigestAlgorithm());
                fileName = token.getOutFileName();
            } else {
                fileName = firstInput.getFileName();
            }
            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), fileName, true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, token.getOutFileName());

            checkDataToSign(parameters, dataToSignForTokenDto.getToken());

            if (!token.isXadesMultifile() && parameters.getSignatureLevel().toString().startsWith("PAdES")) {
                pdfVisibleSignatureService.checkAndFillParams(parameters, fileToSign, firstInput, token.getBucket(), clientSigParams.getPhoto());
            }

            ToBeSignedDTO dataToSign = altSignatureService.getDataToSignWithReferences(fileToSign, parameters, references);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), clientSigParams.getSigningDate());

            logger.info("Returning from getDataToSignForToken()");

            return ret;
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = SIGN_DOCUMENT_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<RemoteDocument> signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDto) {
        try {
            LOG.info("signDocumentForToken");
            TokenObject token = extractToken(signDto.getToken());
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();

            // Signing within allowed time ?
            long signTimeout = token.getSignTimeout() != null ? token.getSignTimeout() * 1000 : SIGN_DURATION_SECS * 1000;
            if (new Date().getTime() >= (clientSigParams.getSigningDate().getTime() + signTimeout)) {
                logAndThrowEx(BAD_REQUEST, SIGN_PERIOD_EXPIRED, "");
            }

            // If a whitelist of allowed national numbers is defined in the token, check if the presented certificate national number is allowed to sign the document
            checkNNAllowedToSign(token.getNnAllowedToSign(), clientSigParams.getSigningCertificate());

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(token.getSignProfile(), clientSigParams, token.getPolicy());

            String fileName;
            List<DSSReference> references = null;
            TokenSignInput firstInput = token.getInputs().get(0);
            if (token.isXadesMultifile()) {
                List<String> idsToSign = new ArrayList<String>(token.getInputs().size());
                for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
                references = buildReferences(clientSigParams.getSigningDate(), idsToSign, parameters.getReferenceDigestAlgorithm());
                fileName = token.getOutFileName();
            } else {
                fileName = firstInput.getFileName();
            }

            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), fileName, true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, token.getOutFileName());
            if (parameters.getSignatureLevel().toString().startsWith("PAdES")) {
                pdfVisibleSignatureService.checkAndFillParams(parameters, fileToSign, firstInput, token.getBucket(), clientSigParams.getPhoto());
            }

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.signDocumentWithReferences(fileToSign, parameters, signatureValueDto, references);
            signedDoc.setName(token.getOutFileName());

            logger.info("signDocumentForToken(): validating the signed doc");
            signedDoc = validateResult(signedDoc, clientSigParams.getDetachedContents(), parameters, token);

            // Save signed file
            storageService.storeFile(token.getBucket(), signedDoc.getName(), signedDoc.getBytes());
            LOG.info("done signDocumentForToken");

            if (token.isOutDownload()) {
                return new ResponseEntity<>(signedDoc, HttpStatus.OK);
            }

        } catch (IOException | NullParameterException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }

        return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);
    }

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters) {
        return validateResult(signedDoc, detachedContents, parameters, null);
    }

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters, TokenObject token) {
        WSReportsDTO reportsDto = validationService.validateDocument(signedDoc, detachedContents, null, parameters);

        if (null != token) {
            try {
                // Instead of saving the entire report, create our own report containing the simple/detailed reports and the signing cert
                byte[] sigingCert = parameters.getSigningCertificate().getEncodedCertificate();
                ReportDTO reportDto = new ReportDTO(reportsDto.getSimpleReport(), reportsDto.getDetailedReport(), sigingCert);

                StringWriter out = new StringWriter();
                ObjectMapper mapper = new ObjectMapper();
                mapper.setDateFormat(reportDateTimeFormat);
                mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
                mapper.writeValue(out, reportDto);

                storageService.storeFile(token.getBucket(), token.getOutFileName() + ".validationreport.json", out.toString().getBytes());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Failed to serialize or save the validation report", e);
            }
        }

        SignatureIndicationsDTO indications = reportsService.getSignatureIndicationsDto(reportsDto);
        Indication indication = indications.getIndication();
        if (indication == TOTAL_PASSED || parameters.isSignWithExpiredCertificate()) {
            return signedDoc;
        } else {
            String subIndication = indications.getSubIndication();
            if (subIndication.equals(CERT_REVOKED))
                logAndThrowEx(BAD_REQUEST, CERT_REVOKED, null, null);
            else
                logAndThrowEx(BAD_REQUEST, INVALID_DOC, String.format("%s, %s", indication, subIndication));
        }
        return null; // We won't get here
    }

    private void checkDataToSign(RemoteSignatureParameters parameters, String tokenString) {

        Date now = new Date();
        // Check if the signing cert is present and not expired
        try {
            RemoteCertificate signingCert = parameters.getSigningCertificate();
            if (null == signingCert)
                logAndThrowEx(BAD_REQUEST, NO_SIGN_CERT, "no signing cert present in request");
            byte[] signingCertBytes = signingCert.getEncodedCertificate();
            if (null == signingCertBytes)
                logAndThrowEx(BAD_REQUEST, NO_SIGN_CERT, "could not get encoded signing cert from request");
            X509Certificate signingCrt = (X509Certificate) CertificateFactory.getInstance("X509")
                    .generateCertificate(new ByteArrayInputStream(signingCertBytes));

            // Log the cert ID, so it can be linked to the tokenString
            if (null != tokenString)
                logger.log(Level.INFO, "Signing certificate ID for " + tokenString + " : " + new CertificateToken(signingCrt).getDSSIdAsString());

            // Don't do the expiry check if the profile says to ignore it (only used for testing)
            if (!parameters.isSignWithExpiredCertificate() && now.after(signingCrt.getNotAfter()))
                logAndThrowEx(BAD_REQUEST, SIGN_CERT_EXPIRED, "exp. date = " + logDateTimeFormat.format(signingCrt.getNotAfter()));
        }
        catch (CertificateException e) {
            logAndThrowEx(BAD_REQUEST, "error parsing signing cert", e.getMessage());
        }

        // Check if the cert chain is present (at least 2 certs)
        List<RemoteCertificate> chain = parameters.getCertificateChain();
        if (null == chain || chain.size() < 2)
            logAndThrowEx(BAD_REQUEST, CERT_CHAIN_INCOMPLETE, "cert count: " + chain.size());
    }


    // Create a "token" based of n the CreateSignFlowDTO. This will be the driver for the whole process
    private String createToken(TokenObject token)  {
        try {
            // JSONify & GZIP object
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            token.setCreateTime(new Date().getTime());
            new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValue(new GZIPOutputStream(bos), token);

            // Create new symetric Key
            KeyGenerator keygen = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGO);
            keygen.init(256);
            SecretKey newKey = keygen.generateKey();

            // Create new random KeyID
            byte[] kidBytes = new byte[9];
            new SecureRandom().nextBytes(kidBytes);
            String keyId = Base64.getUrlEncoder().encodeToString(kidBytes);
            // Store key in secret bucket
            storageService.storeFile(null, KEYS_FOLDER + keyId, newKey.getEncoded());
            keyCache.put(keyId, newKey);

            // Pack all into a JWE & Encrypt
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                    .keyID(keyId)
                    .build(), new Payload(bos.toByteArray()));
            jweObject.encrypt(new DirectEncrypter(newKey));
            String tokenString = jweObject.serialize();
            logger.info(tokenString);
            return tokenString;
        } catch (IOException | NoSuchAlgorithmException | JOSEException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null;
    }

    // Extract and decrypt a "token"
    private TokenObject extractToken(String tokenString) {
        try {
            JWEObject jweObject = JWEObject.parse(tokenString);
            String keyId = jweObject.getHeader().getKeyID();
            SecretKey key = keyCache.getIfPresent(keyId);
            if (key == null) {
                byte rawKey[] = storageService.getFileAsBytes(null, KEYS_FOLDER + keyId, false);
                key = new SecretKeySpec(rawKey, SYMMETRIC_KEY_ALGO);
            }
            jweObject.decrypt(new DirectDecrypter(key));
            GZIPInputStream zis = new GZIPInputStream(new ByteArrayInputStream(jweObject.getPayload().toBytes()));
            TokenObject token = new ObjectMapper().readValue(zis, TokenObject.class);

            if (new Date().getTime() > (token.getCreateTime() + TOKEN_VALIDITY_SECS * 60000)) {
                logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, "Token is expired");
            }
            return token;
        } catch(ParseException | IOException | JOSEException | StorageService.InvalidKeyConfigException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, e);
        }
        return  null;
    }

    private void checkNNAllowedToSign(List<String> nnAllowedToSign, RemoteCertificate signingCertificate) {
        if (nnAllowedToSign != null) {
            CertInfo certInfo = new CertInfo(signingCertificate);
            String nn = certInfo.getSerialNumber();
            if (!nnAllowedToSign.contains(nn)) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, "NN not allowed to sign");
            }
        }
    }

    private List<String> getIdsToSign(List<SignElement> elementsToSign) {
        List<String> list = new ArrayList<String>(elementsToSign.size());
        for(SignElement elementToSign : elementsToSign) list.add(elementToSign.getId());
        return list;
    }

    private List<DSSReference> buildReferences(Date signingTime, List<String> xmlIds, DigestAlgorithm refDigestAlgo) {
        String timeRef = Long.toString(signingTime.getTime());
        List<DSSReference> references = new ArrayList<DSSReference>();
        int count = 0;
        for(String xmlId : xmlIds) {
            DSSReference reference = new DSSReference();
            reference.setId("id_" + timeRef + "_" + Integer.toString(count++));
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

    /*****************************************************************************************
     *
     * NON-TOKEN Signing services
     *
     ****************************************************************************************/

    @PostMapping(value = GET_DATA_TO_SIGN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        try {
            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters(), null);

            checkDataToSign(parameters, null);

            ToBeSignedDTO dataToSign = altSignatureService.getDataToSign(dataToSignDto.getToSignDocument(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), dataToSignDto.getClientSignatureParameters().getSigningDate());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureException e) {
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


    @PostMapping(value = "/getDataToSignMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignMultiple(@RequestBody GetDataToSignMultipleDTO dataToSignDto) {
        try {
            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters(), null);

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), dataToSignDto.getClientSignatureParameters().getSigningDate());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters(), null);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.signDocument(signDocumentDto.getToSignDocument(), parameters, signatureValueDto);

            return validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/signDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentMultiple(@RequestBody SignDocumentMultipleDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters(), null);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDocumentDto.getToSignDocuments(), parameters, signatureValueDto);

            return validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = EXTEND_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = altSignatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            return validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = EXTEND_DOCUMENT_MULTIPLE, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocumentMultiple(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = signatureServiceMultiple.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            return validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } 
        return null; // We won't get here
    }

    @PostMapping(value = TIMESTAMP_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        try {
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            return altSignatureService.timestamp(timestampDocumentDto.getDocument(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = TIMESTAMP_DOCUMENT_MULTIPLE, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocumentMultiple(@RequestBody TimestampDocumentMultipleDTO timestampDocumentDto) {
        try {
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            return signatureServiceMultiple.timestamp(timestampDocumentDto.getDocuments(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = GET_DATA_TO_SIGN_XADES_MULTI_DOC, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
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

    @PostMapping(value = SIGN_DOCUMENT_XADES_MULTI_DOC, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
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
}
