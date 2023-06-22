package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.*;
import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.utils.MediaTypeUtil;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.exception.NullParameterException;
import com.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.bosa.signingconfigurator.model.PolicyParameters;
import com.bosa.signingconfigurator.service.SigningConfiguratorService;
import com.bosa.signandvalidation.config.ErrorStrings;
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
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.*;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

import static com.bosa.signandvalidation.exceptions.Utils.getTokenFootprint;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static com.bosa.signandvalidation.model.SigningType.XadesMultiFile;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import eu.europa.esig.dss.enumerations.Indication;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.*;

import org.springframework.http.ResponseEntity;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

@RestController
@RequestMapping(value = SigningController.ENDPOINT)
public class SigningController extends ControllerBase implements ErrorStrings {

    // Service URL
    public static final String ENDPOINT                         = "/signing";

    public static final String PING                             = "/ping";
    // Token operations
    public static final String GET_TOKEN_FOR_DOCUMENT           = "/getTokenForDocument";
    public static final String GET_TOKEN_FOR_DOCUMENTS          = "/getTokenForDocuments";
    public static final String GET_DATA_TO_SIGN_FOR_TOKEN       = "/getDataToSignForToken";
    public static final String GET_METADATA_FOR_TOKEN           = "/getMetadataForToken";
    public static final String GET_FILE_FOR_TOKEN               = "/getFileForToken";
    public static final String SIGN_DOCUMENT_FOR_TOKEN          = "/signDocumentForToken";

    public static final int DEFAULT_TOKEN_VALIDITY_SECS         = 5 * 60 * 60;
    public static final int DEFAULT_SIGN_DURATION_SECS          = 2 * 60;
    public static final int MAX_NN_ALLOWED_TO_SIGN              = 32;
    private static final Pattern nnPattern                      = Pattern.compile("[0-9]{11}");
    private static final Pattern eltIdPattern                   = Pattern.compile("[a-zA-Z0-9\\-_]{1,30}");

    private static final List<String> allowedLanguages          =  Arrays.asList("fr", "de", "nl", "en");

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
    private static final String KEYS_FILENAME_EXTENTION         = ".json";
    private static final String SYMMETRIC_KEY_ALGO              = "AES";

    private static final SimpleDateFormat logDateTimeFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
    // Secret key cache
    private static final Cache<String, SecretKey> keyCache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).build();

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

    @Autowired
    private Environment environment;

    @Value("${signing.time}")
    private Long signingTime;

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
            // Password not needed anymore
            tokenData.setPwd(null);

            List<TokenSignInput> inputs = new ArrayList<>();
            TokenSignInput input = new TokenSignInput();
            input.setFilePath(tokenData.getIn());
            input.setSignLanguage(tokenData.getLang());
            input.setPspFilePath(tokenData.getPsp());
            input.setPsfP(Boolean.parseBoolean(tokenData.getPsfP()));
            input.setPsfC(tokenData.getPsfC());
            input.setPsfN(tokenData.getPsfN());
            input.setDisplayXsltPath(tokenData.getXslt());
            inputs.add(input);

            String pdfProfile = tokenData.getProf();
            String xmlProfile = pdfProfile;
            if (pdfProfile != null && pdfProfile.startsWith("PADES")) xmlProfile = null;
            else pdfProfile = null;

            TokenObject token = new TokenObject(SigningType.Standard, tokenData.getName(), pdfProfile, xmlProfile, inputs, tokenData.getOut());
            if (tokenData.getPolicyId() != null) {
                String policyAlgorithm = tokenData.getPolicyDigestAlgorithm();
                token.setPolicy(new PolicyParameters(tokenData.getPolicyId(), tokenData.getPolicyDescription(), policyAlgorithm == null ? null : DigestAlgorithm.valueOf(policyAlgorithm)));
            }
            token.setPreviewDocuments(true);
            token.setOutDownload(!tokenData.isNoDownload());
            token.setRequestDocumentReadConfirm(tokenData.isRequestDocumentReadConfirm());
            token.setSignTimeout(tokenData.getSignTimeout());
            if (tokenData.getAllowedToSign() != null) {
                List<String> nnAllowedToSign = new ArrayList<>();
                for(AllowedToSign allowedToSign : tokenData.getAllowedToSign()) {
                    nnAllowedToSign.add(allowedToSign.getNN());
                }
                token.setNnAllowedToSign(nnAllowedToSign);
            }

            checkTokenAndSetDefaults(token);

            String tokenString = createToken(token);
            logger.info("Returning from getTokenForDocument()" + getTokenFootprint(tokenString) + " params: " + objectToString(tokenData));
            return tokenString;
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

     @PostMapping(value = GET_TOKEN_FOR_DOCUMENTS, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocuments(@RequestBody GetTokenForDocumentsDTO gtfd) {
        // Validate input
        if(!(storageService.isValidAuth(gtfd.getBucket(), gtfd.getPassword()))) {
            logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
        }
        // Password not needed anymore
        gtfd.setPassword(null);

        SigningType signingType = gtfd.getSignType();
         if (signingType == null) signingType = SigningType.XadesMultiFile;
        List<TokenSignInput> tokenInputs = new ArrayList<>();
        for(SignInput input : gtfd.getInputs()) {
            TokenSignInput ti = new TokenSignInput();
            ti.setFilePath(input.getFilePath());
            ti.setXmlEltId(input.getXmlEltId());
            ti.setDisplayXsltPath(input.getDisplayXsltPath());
            ti.setPspFilePath(input.getPspFilePath());
            ti.setSignLanguage(input.getSignLanguage());
            ti.setPsfC(input.getPsfC());
            ti.setPsfN(input.getPsfN());
            ti.setPsfP(input.isPsfP());
            tokenInputs.add(ti);
        }

         String pdfProfile = searchProfile("PADES", gtfd);
         String xmlProfile = searchProfile("XADES", gtfd);
        TokenObject token = new TokenObject(signingType, gtfd.getBucket(), pdfProfile, xmlProfile, tokenInputs, gtfd.getOutFilePath());
        token.setSignTimeout(gtfd.getSignTimeout() );
        token.setNnAllowedToSign(gtfd.getNnAllowedToSign());
        PolicyDTO policy = gtfd.getPolicy();
        if (policy != null) {
            token.setPolicy(new PolicyParameters(policy.getId(), policy.getDescription(), policy.getDigestAlgorithm()));
        }
        token.setOutXsltPath(gtfd.getOutXsltPath());
        token.setOutDownload(gtfd.isOutDownload());
        token.setOutPathPrefix(gtfd.getOutPathPrefix());
        token.setRequestDocumentReadConfirm(gtfd.isRequestDocumentReadConfirm());
        token.setPreviewDocuments(gtfd.isPreviewDocuments());
         token.setSelectDocuments(gtfd.isSelectDocuments());
         token.setNoSkipErrors(gtfd.isNoSkipErrors());

        checkTokenAndSetDefaults(token);

        if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
            createXadesMultifileToBeSigned(token);
        }

        // Create Token
        String tokenString = createToken(token);
        logger.info("Returning from getTokenForDocuments()" + getTokenFootprint(tokenString) + " params: " + objectToString(gtfd));
        return tokenString;
    }

    /*****************************************************************************************/

    private String searchProfile(String profileSearch, GetTokenForDocumentsDTO gtfd) {
        String profile = gtfd.getSignProfile();
        if (profile != null && profile.contains(profileSearch)) return profile;
        profile = gtfd.getAltSignProfile();
        return profile != null && profile.contains(profileSearch) ? profile : null;
    }

    /*****************************************************************************************/

    private static String objectToString(Object input) {
        try {
            return new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(input);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return e.toString();
        }
    }

    /*****************************************************************************************/

    void checkTokenAndSetDefaults(TokenObject token) {

        if (token.getPdfSignProfile() == null && token.getXmlSignProfile() == null) {
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

        Integer tokenTimeout = token.getTokenTimeout();
        if (tokenTimeout == null) token.setTokenTimeout(tokenTimeout = DEFAULT_TOKEN_VALIDITY_SECS);

        Integer signTimeout = token.getSignTimeout();
        if (signTimeout == null) token.setSignTimeout(signTimeout = DEFAULT_SIGN_DURATION_SECS);
        if (signTimeout > tokenTimeout) {
            logAndThrowEx(FORBIDDEN, SIGN_PERIOD_EXPIRED, "signTimeout (" + signTimeout + ") can't be larger than  Token expiration (" + tokenTimeout + ")" , null);
        }

        List<String> nnsAllowedToSign = token.getNnAllowedToSign();
        if (nnsAllowedToSign != null) {
            if (nnsAllowedToSign.size() > MAX_NN_ALLOWED_TO_SIGN) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "nnAllowedToSign (" + nnsAllowedToSign.size() + ") can't be larger than MAX_NN_ALLOWED_TO_SIGN (" + MAX_NN_ALLOWED_TO_SIGN + ")" , null);
            }
            List<String> nnList = new ArrayList<String>();
            for(String nnAllowedToSign : nnsAllowedToSign) {
                checkValue("nnAllowedToSign", nnAllowedToSign, false, nnPattern, nnList);
            }
        }

        List<TokenSignInput> inputs = token.getInputs();
        if (inputs == null || inputs.size() == 0) {
            logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'inputs' field is empty" , null);
        }
        List<String> filenamesList = new ArrayList<String>();
        List<String> eltIdList = new ArrayList<String>();
        for(TokenSignInput input : inputs) {
            checkValue("fileName", input.getFilePath(), false, null, filenamesList);

            MediaType inputFileType = MediaTypeUtil.getMediaTypeFromFilename(input.getFilePath());
            boolean isPDF = APPLICATION_PDF.equals(inputFileType);
            boolean isXML = APPLICATION_XML.equals(inputFileType);
            if (!isPDF && !isXML) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "input files must be either XML or PDF", null);
            }

            if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
                checkValue("XmlEltId", input.getXmlEltId(), false, eltIdPattern, eltIdList);
                if (input.getPsfN() != null || input.getPsfC() != null || input.getSignLanguage() != null || input.getPspFilePath() != null) {
                    logAndThrowEx(FORBIDDEN, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for Multifile Xades", null);
                }
            } else {
                if (input.getXmlEltId() != null) {
                    logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'XmlEltId' must be null for 'non Xades Multifile'", null);
                }

                if ((isPDF && token.getPdfSignProfile() == null) || (isXML && token.getXmlSignProfile() == null)) {
                    logAndThrowEx(FORBIDDEN, INVALID_PARAM, "No signProfile for file type provided (" + inputFileType.toString() + " => " + token.getPdfSignProfile() + "/" + token.getXmlSignProfile() + ")", null);
                }

                if (isPDF) {
                    String signLanguage = input.getSignLanguage();
                    if (signLanguage != null && !allowedLanguages.contains(signLanguage)) {
                        logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'SignLanguage' (" + signLanguage + ") must be one of " + String.join(", ", allowedLanguages), null);
                    }
                    // TODO Validate  PSFxxx, psp, ... fields
                }
            }
            if (!isXML && input.getDisplayXsltPath() != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "DisplayXslt must be null for non-xml files", null);
            }
        }

        String prefix = token.getOutPathPrefix();
        if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
            if (!"MDOC_XADES_LTA".equals(token.getXmlSignProfile())) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'Xades Multifile' with an invalid signProfile :" + token.getXmlSignProfile(), null);
            }

            if (prefix != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outPathPrefix' must be null for 'Xades Multifile'", null);
            }

            checkValue("OutXslt", token.getOutXsltPath(), true, null, filenamesList);
            if (token.isSelectDocuments()) {
                // Xades Multifile signs all files at the same time so can't have "cherry picked" files without large changes
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Can't individually select documents for 'Xades Multifile'", null);
            }
        } else {
            if (inputs.size() > 1 && !token.isPreviewDocuments()) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "previewDocuments must be 'true' for non 'Xades Multifile' signature", null);
            }

            if (token.getOutXsltPath() != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outXslt' must be null for non 'Xades Multifile'", null);
            }
        }

        String outPath = token.getOutFilePath();
        if (outPath != null && outPath.length() == 0) token.setOutFilePath(outPath = null);

            if (prefix != null) {
            if (prefix.endsWith("/")) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outPathPrefix' can't end with '/'", null);
            }

            if (outPath != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outFilePath' must be null if outPathPrefix is set (Bulk Signing)", null);
            }
            // TODO : Check "prefixed" names collisions
        } else {
            checkValue("outFilePath", outPath, false, null, filenamesList);
        }
    }

    /*****************************************************************************************/

    private static void checkValue(String name, String value, boolean nullable, Pattern patternToMatch, List<String> uniqueList) {
        if (value != null) {
            if (uniqueList != null) {
                if (uniqueList.contains(value)) {
                    logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'" + name + "' (" + value + ") is not unique", null);
                }
                uniqueList.add(value);
            }
            if (patternToMatch != null) {
                if (!patternToMatch.matcher(value).matches()) {
                    logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'" + name + "' (" + value + ") does not match Regex (" + patternToMatch.pattern() + ")" , null);
                }
            }
        } else {
            if (!nullable) {
                logAndThrowEx(FORBIDDEN, EMPTY_PARAM, "'" + name + "' is NULL", null);
            }
        }
    }

    /*****************************************************************************************/

    private void createXadesMultifileToBeSigned(TokenObject token) {
        try {
            logger.info("Creating Xades xml file : " + token.getOutFilePath());

            // Create BOSA XML Template
            XadesFileRoot root = new XadesFileRoot();
            for(TokenSignInput input : token.getInputs()) {
                XadesFile file = new XadesFile();
                file.setName(input.getFilePath());
                file.setId(input.getXmlEltId());
                file.setSize(storageService.getFileInfo(token.getBucket(), input.getFilePath()).getSize());
                root.getFiles().add(file);
            }
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            JAXBContext context = JAXBContext.newInstance(XadesFileRoot.class);

            Document doc = dbf.newDocumentBuilder().newDocument();
            context.createMarshaller().marshal(root, doc);

            //logger.info(XmlUtil.xmlDocToString(doc));

            TransformerFactory tf = new net.sf.saxon.BasicTransformerFactory();
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

            // If requested create target file
            String xsltPath = token.getOutXsltPath();
            if (xsltPath != null) {
                // XSLT present -> transform to proprietary format
                DOMResult xsltDom = new DOMResult();
                InputStream xsltStream = storageService.getFileAsStream(token.getBucket(), xsltPath);
                tf.newTransformer(new StreamSource(xsltStream)).transform(new DOMSource(doc), xsltDom);
                doc = (Document)xsltDom.getNode();

                //logger.info(XmlUtil.xmlDocToString(doc));
            }

            putFilesContent(doc.getFirstChild(), token);

            //logger.info(XmlUtil.xmlDocToString(doc));

            // Save target XML to bucket
            ByteArrayOutputStream outStream = new ByteArrayOutputStream(32768);
            tf.newTransformer().transform(new DOMSource(doc), new StreamResult(outStream));
            storageService.storeFile(token.getBucket(), token.getOutFilePath(), outStream.toByteArray());

            logger.info("Done creating xml file : " + token.getOutFilePath());

        } catch (JAXBException | TransformerException | ParserConfigurationException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
    }

    /*****************************************************************************************/

    private void putFilesContent(Node node, TokenObject token) {
        while(node != null) {
            putFilesContent(node.getFirstChild(), token);
            // Since "Node.getAttributes()" implementation does not respect @NotNull contract... we must check that the attributes are not null to avoid NPE from getIDIdentifier
            if (node.getAttributes() != null) {
                // Use DSS libraries to identify ID XML attributes
                String id = DSSXMLUtils.getIDIdentifier(node);
                if (id != null) {
                    for (TokenSignInput input : token.getInputs()) {
                        if (id.compareTo(input.getXmlEltId()) == 0) {
                            node.setTextContent(storageService.getFileAsB64String(token.getBucket(), input.getFilePath()));
                            break;
                        }
                    }
                }
            }
            node = node.getNextSibling();
        }
    }

    /*****************************************************************************************/

    @GetMapping(value = GET_METADATA_FOR_TOKEN)
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String tokenString) {
        String tokenFootprint = getTokenFootprint(tokenString);
        logger.info("Entering getMetadataForToken()" + tokenFootprint);
            try {
                TokenObject token = extractToken(tokenString);
                List<SignInputMetadata> signedInputsMetadata = new ArrayList<>();
                for(TokenSignInput input : token.getInputs()) {
                    SignInputMetadata inputMetadata = new SignInputMetadata();
                    inputMetadata.setFileName(getNameFromPath(input.getFilePath()));
                    inputMetadata.setMimeType(MediaTypeUtil.getMediaTypeFromFilename(input.getFilePath()).toString());
                    inputMetadata.setHasDisplayXslt(input.getDisplayXsltPath() != null);
                    signedInputsMetadata.add(inputMetadata);
                }

                boolean getPhoto = false;
                for(TokenSignInput input : token.getInputs()) getPhoto |= input.isPsfP();

                logger.info("Returning from getMetadataForToken()" + tokenFootprint);
                return new DocumentMetadataDTO(token.getSigningType(), getPhoto, !token.isOutDownload(),
                        token.isRequestDocumentReadConfirm(), token.isPreviewDocuments(), token.isSelectDocuments(), token.isNoSkipErrors(), signedInputsMetadata);

            } catch (RuntimeException e){
                    logAndThrowEx(tokenString, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
            }
            return null; // We won't get here
    }

    /*****************************************************************************************/

    private static String getNameFromPath(String filePath) {
        int pos = filePath.lastIndexOf("/");
        return pos == -1 ? filePath : filePath.substring(pos + 1);
    }

    /*****************************************************************************************/

    @GetMapping(value = GET_FILE_FOR_TOKEN + "/{token}/{type}/{inputIndexes}")
    public void getFileForToken(@PathVariable("token") String tokenString,
                                @PathVariable GetFileType type,
                                @PathVariable(required = true) Integer inputIndexes[],
                                @RequestParam(required = false)  String forceDownload,
                                HttpServletResponse response) {

        TokenObject token = extractToken(tokenString);

        String singleFilePath = null;
        TokenSignInput input = token.getInputs().get(inputIndexes[0]);
        switch (type) {
            case DOC:
                singleFilePath = input.getFilePath();
                break;
            case XSLT:
                singleFilePath = input.getDisplayXsltPath();
                break;
            case OUT:
                if (!token.isOutDownload()) {
                    logAndThrowEx(tokenString, BAD_REQUEST, BLOCKED_DOWNLOAD, "Forging request attempt !");
                }
                if (token.getSigningType().equals(XadesMultiFile) || inputIndexes.length == 1) singleFilePath = getOutFilePath(token, input);
                break;
        }

        ZipOutputStream out = null;
        InputStream fileStream = null;
        try {
            MediaType contentType = null;
            String attachmentName = null;
            if (singleFilePath != null) {
                attachmentName = getNameFromPath(singleFilePath);
                FileStoreInfo fi = storageService.getFileInfo(token.getBucket(), singleFilePath);
                contentType = fi.getContentType();
            } else {
                contentType = APPLICATION_OCTET_STREAM;
                attachmentName = "FTS" + new SimpleDateFormat("yyyyMMDD HHmmss").format(new Date()) + ".zip";
            }

            String contentDisposition = forceDownload != null || !contentType.equals(APPLICATION_PDF) ? "attachment; filename=\"" + attachmentName + "\"" : "inline";
            response.setContentType(contentType.toString());
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Cache-Control", "no-cache");
            response.setHeader("Content-Transfer-Encoding", "binary");
            response.setHeader("Content-Disposition", contentDisposition);

            if (singleFilePath != null) {
                fileStream = storageService.getFileAsStream(token.getBucket(), singleFilePath);
                Utils.copy(fileStream, response.getOutputStream());
            } else {
                out = new ZipOutputStream(response.getOutputStream());
                for(Integer inputId : inputIndexes) {
                    String fileNameToZip = getNameFromPath(getOutFilePath(token, token.getInputs().get(inputId)));
                    out.putNextEntry(new ZipEntry(fileNameToZip));
                    fileStream = storageService.getFileAsStream(token.getBucket(), fileNameToZip);
                    Utils.copy(fileStream, out);
                    out.closeEntry();
                    fileStream.close();
                }
                out.close();
            }
            fileStream.close();
        } catch (IOException e) {
            logAndThrowEx(tokenString, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            if (fileStream != null) {
                try {
                    fileStream.close();
                } catch (IOException ignored) { }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) { }
            }
        }
    }

    /*****************************************************************************************/

    @PostMapping(value = GET_DATA_TO_SIGN_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        String tokenString = dataToSignForTokenDto.getToken();
        String tokenFootprint = getTokenFootprint(tokenString);
        logger.info("Entering getDataToSignForToken()" + tokenFootprint);
        try {
            TokenObject token = extractToken(dataToSignForTokenDto.getToken());
            ClientSignatureParameters clientSigParams = dataToSignForTokenDto.getClientSignatureParameters();

            // Signer allowed to sign ?
            checkNNAllowedToSign(token.getNnAllowedToSign(), clientSigParams.getSigningCertificate());

            Date signingDate = signingTime == null ? new Date() : new Date(signingTime);
            clientSigParams.setSigningDate(signingDate);

            String filePath;
            MediaType mediaType = null;
            TokenSignInput inputToSign = null;
            List<DSSReference> references = null;
            RemoteSignatureParameters parameters = null;
            if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
                String profile = token.getXmlSignProfile();
                if (profile == null) {
                    // Double check that profile is not NULL to avoid default being used
                    logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, "Profile is null, aborting !");
                }
                parameters = signingConfigService.getSignatureParams(profile, clientSigParams, token.getPolicy());
                List<String> idsToSign = new ArrayList<String>(token.getInputs().size());
                for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
                references = buildReferences(signingDate, idsToSign, parameters.getReferenceDigestAlgorithm());
                filePath = token.getOutFilePath();
            } else {
                inputToSign = token.getInputs().get(dataToSignForTokenDto.getFileIdToSign());
                filePath = inputToSign.getFilePath();
                mediaType = MediaTypeUtil.getMediaTypeFromFilename(filePath);
                String profile = APPLICATION_PDF.equals(mediaType) ? token.getPdfSignProfile() : token.getXmlSignProfile();
                if (profile == null) {
                    // Double check that profile is not NULL to avoid default being used
                    logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, "Profile is null, aborting !");
                }
                parameters = signingConfigService.getSignatureParams(profile, clientSigParams, token.getPolicy());
            }

            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, null);

            checkDataToSign(parameters, dataToSignForTokenDto.getToken());

            if (mediaType != null && APPLICATION_PDF.equals(mediaType)) {
                pdfVisibleSignatureService.checkAndFillParams(parameters, fileToSign, inputToSign, token.getBucket(), clientSigParams);
            }

            ToBeSignedDTO dataToSign = altSignatureService.getDataToSignWithReferences(fileToSign, parameters, references);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), clientSigParams.getSigningDate());

            logger.info("Returning from getDataToSignForToken()" + tokenFootprint);

            return ret;
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch (Exception e) {
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @PostMapping(value = SIGN_DOCUMENT_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<RemoteDocument> signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDto) {
        try {
            String tokenFootprint = getTokenFootprint(signDto.getToken());
            logger.info("Entering signDocumentForToken()" + tokenFootprint);

            TokenObject token = extractToken(signDto.getToken());
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();

            // Signing within allowed time ?
            Date now = signingTime == null ? new Date() : new Date(signingTime);

            long expiredBy = now.getTime() - token.getSignTimeout() * 1000L - clientSigParams.getSigningDate().getTime();
            if (expiredBy > 0) {
                logAndThrowEx(BAD_REQUEST, SIGN_PERIOD_EXPIRED, "Expired by :" + Long.toString(expiredBy / 1000) + " seconds");
            }

            // If a whitelist of allowed national numbers is defined in the token, check if the presented certificate national number is allowed to sign the document
            checkNNAllowedToSign(token.getNnAllowedToSign(), clientSigParams.getSigningCertificate());

            String filePath;
            MediaType mediaType = null;
            TokenSignInput inputToSign = null;
            List<DSSReference> references = null;
            RemoteSignatureParameters parameters = null;
            if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
                parameters = signingConfigService.getSignatureParams(token.getXmlSignProfile(), clientSigParams, token.getPolicy());
                List<String> idsToSign = new ArrayList<String>(token.getInputs().size());
                for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
                references = buildReferences(clientSigParams.getSigningDate(), idsToSign, parameters.getReferenceDigestAlgorithm());
                filePath = token.getOutFilePath();
            } else {
                inputToSign = token.getInputs().get(signDto.getFileIdToSign());
                filePath = inputToSign.getFilePath();
                mediaType = MediaTypeUtil.getMediaTypeFromFilename(filePath);
                String profile = APPLICATION_PDF.equals(mediaType) ? token.getPdfSignProfile() : token.getXmlSignProfile();
                parameters = signingConfigService.getSignatureParams(profile, clientSigParams, token.getPolicy());
            }

            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, null);
            if (mediaType != null && APPLICATION_PDF.equals(mediaType)) {
                pdfVisibleSignatureService.checkAndFillParams(parameters, fileToSign, inputToSign, token.getBucket(), clientSigParams);
            }

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.signDocumentWithReferences(fileToSign, parameters, signatureValueDto, references);

            signedDoc.setName(getOutFilePath(token, inputToSign));

            logger.info("signDocumentForToken(): validating the signed doc" + tokenFootprint);
            signedDoc = validateResult(signedDoc, clientSigParams.getDetachedContents(), parameters, token, signedDoc.getName(), null);

            // Save signed file
            storageService.storeFile(token.getBucket(), signedDoc.getName(), signedDoc.getBytes());

            MDC.put("bucket", token.getBucket());
            MDC.put("fileName", signedDoc.getName());
            logger.info("Returning from signDocumentForToken().");
            MDC.remove("bucket");
            MDC.remove("fileName");

        } catch (Exception e) {
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }

        return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);
    }

    /*****************************************************************************************/

    private static String getOutFilePath(TokenObject token, TokenSignInput inputToSign) {
        String prefix = token.getOutPathPrefix();
        return (prefix == null) ? token.getOutFilePath() : prefix + inputToSign.getFilePath();
    }

    /*****************************************************************************************/

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters, RemoteDocument validatePolicy) {
        return validateResult(signedDoc, detachedContents, parameters, null, null, validatePolicy);
    }

    /*****************************************************************************************/

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters, TokenObject token, String outFilePath, RemoteDocument validatePolicy) {
        WSReportsDTO reportsDto = validationService.validateDocument(signedDoc, detachedContents, validatePolicy, parameters);

        if (null != token) {
            try {
                storageService.storeFile(token.getBucket(), outFilePath + ".validationreport.json",
                        reportsService.createJSONReport(parameters, reportsDto).getBytes());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Failed to serialize or save the validation report", e);
            }
        }

        SignatureIndicationsDTO indications = token == null ?
                reportsService.getSignatureIndicationsDto(reportsDto) :
                reportsService.getLatestSignatureIndicationsDto(reportsDto, new Date(token.getCreateTime()));

        Indication indication = indications.getIndication();
        if (indication != TOTAL_PASSED) {
            // When running in a "local" profile dump the signing report
            for(String profile : this.environment.getActiveProfiles()) {
                if ("local".equals(profile)) {
                    try {
                        logger.severe(reportsService.createJSONReport(parameters, reportsDto));
                    } catch (IOException e) {
                        logger.severe("Can't log report !!!!!!!!");
                    }
                }
            }
            if (!parameters.isSignWithExpiredCertificate()) {
                String subIndication = indications.getSubIndicationLabel();
                if (CERT_REVOKED.compareTo(subIndication) == 0) {
                    logAndThrowEx(BAD_REQUEST, CERT_REVOKED, null, null);
                }
                DataLoadersExceptionLogger.logAndThrow();
                logAndThrowEx(BAD_REQUEST, INVALID_DOC, String.format("%s, %s", indication, subIndication));
            }
        }
        return signedDoc;
    }

    /*****************************************************************************************/

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
                logger.info("Signing certificate ID for " + tokenString + " : " + new CertificateToken(signingCrt).getDSSIdAsString());

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

    /*****************************************************************************************/
    // Create a "token" based of n the CreateSignFlowDTO. This will be the driver for the whole process

    String createToken(TokenObject token)  {
        try {
            // JSONify & GZIP object
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            token.setCreateTime(new Date().getTime());
            ObjectMapper om = new ObjectMapper();
            om.setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValue(new GZIPOutputStream(bos), token);

            // Create new symetric Key
            KeyGenerator keygen = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGO);
            keygen.init(256);
            SecretKey newKey = keygen.generateKey();

            // Create new random KeyID
            byte[] kidBytes = new byte[9];
            new SecureRandom().nextBytes(kidBytes);
            String keyId = Base64.getUrlEncoder().encodeToString(kidBytes);
            // Store key in secret bucket
            byte[] jsonKey = om.writeValueAsBytes(newKey.getEncoded());
            storageService.storeFile(null, KEYS_FOLDER + keyId + KEYS_FILENAME_EXTENTION, jsonKey);
            keyCache.put(keyId, newKey);

            // Pack all into a JWE & Encrypt
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                    .keyID(keyId)
                    .build(), new Payload(bos.toByteArray()));
            jweObject.encrypt(new DirectEncrypter(newKey));
            return jweObject.serialize();
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }

        return null;
    }

    /*****************************************************************************************/

    // Extract and decrypt a "token"
    private TokenObject extractToken(String tokenString) {
        try {
            ObjectMapper om = new ObjectMapper();
            JWEObject jweObject = JWEObject.parse(tokenString);
            String keyId = jweObject.getHeader().getKeyID();
            SecretKey key = keyCache.getIfPresent(keyId);
            if (key == null) {
                byte[] rawKey = storageService.getFileAsBytes(null, KEYS_FOLDER + keyId + KEYS_FILENAME_EXTENTION, false);
                key = new SecretKeySpec(om.readValue(rawKey, byte[].class), SYMMETRIC_KEY_ALGO);
                keyCache.put(keyId, key);
            }
            jweObject.decrypt(new DirectDecrypter(key));
            GZIPInputStream zis = new GZIPInputStream(new ByteArrayInputStream(jweObject.getPayload().toBytes()));
            TokenObject token = om.readValue(zis, TokenObject.class);

            if (new Date().getTime() > (token.getCreateTime() + token.getTokenTimeout() * 1000L)) {
                logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, "Token is expired");
            }
            return token;
        } catch(ParseException | IOException | JOSEException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, e);
        }
        return  null;
    }

    /*****************************************************************************************/

    private void checkNNAllowedToSign(List<String> nnAllowedToSign, RemoteCertificate signingCertificate) {
        if (nnAllowedToSign != null) {
            CertInfo certInfo = new CertInfo(signingCertificate);
            String nn = certInfo.getSerialNumber();
            if (!nnAllowedToSign.contains(nn)) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, NOT_ALLOWED_TO_SIGN, "NN not allowed to sign");
            }
        }
    }

    /*****************************************************************************************/

    private List<String> getIdsToSign(List<SignElement> elementsToSign) {
        List<String> list = new ArrayList<String>(elementsToSign.size());
        for(SignElement elementToSign : elementsToSign) list.add(elementToSign.getId());
        return list;
    }

    /*****************************************************************************************/

    private List<DSSReference> buildReferences(Date signingTime, List<String> xmlIds, DigestAlgorithm refDigestAlgo) {
        String timeRef = Long.toString(signingTime.getTime());
        List<DSSReference> references = new ArrayList<DSSReference>();
        int count = 0;
        for(String xmlId : xmlIds) {
            DSSReference reference = new DSSReference();
            reference.setId(String.format("id_%s_%d", timeRef, count++));
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

    /*****************************************************************************************
     *
     * NON-TOKEN Signing services
     *
     ****************************************************************************************/

    @PostMapping(value = GET_DATA_TO_SIGN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        logger.info("Entering getDataToSign()");
        try {
            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            ClientSignatureParameters clientSigParams = dataToSignDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), clientSigParams, null);

            checkDataToSign(parameters, null);

            pdfVisibleSignatureService.checkAndFillParams(parameters, dataToSignDto.getToSignDocument(), clientSigParams);

            ToBeSignedDTO dataToSign = altSignatureService.getDataToSign(dataToSignDto.getToSignDocument(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSign()");
            return ret;
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

    /*****************************************************************************************/

    @PostMapping(value = "/getDataToSignMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignMultiple(@RequestBody GetDataToSignMultipleDTO dataToSignDto) {
        try {
            logger.info("Entering getDataToSignMultiple()");
            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters(), null);

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSignMultiple()");
            return ret;
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

    /*****************************************************************************************/

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        try {
            logger.info("Entering signDocument()");
            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), clientSigParams, null);

            pdfVisibleSignatureService.checkAndFillParams(parameters, signDocumentDto.getToSignDocument(), clientSigParams);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.signDocument(signDocumentDto.getToSignDocument(), parameters, signatureValueDto);

            RemoteDocument ret =  validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents(), parameters, signDocumentDto.getValidatePolicy());
            logger.info("Returning from signDocument()");
            return ret;
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

    /*****************************************************************************************/

    @PostMapping(value = "/signDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentMultiple(@RequestBody SignDocumentMultipleDTO signDocumentDto) {
        try {
            logger.info("Entering signDocumentMultiple()");
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters(), null);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDocumentDto.getToSignDocuments(), parameters, signatureValueDto);

            RemoteDocument ret = validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents(), parameters, null);
            logger.info("Returning from signDocumentMultiple()");
            return ret;
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

    /*****************************************************************************************/

    @PostMapping(value = EXTEND_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            logger.info("Entering extendDocument()");
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = altSignatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null);
            logger.info("Returning from extendDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @PostMapping(value = EXTEND_DOCUMENT_MULTIPLE, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocumentMultiple(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            logger.info("Entering extendDocumentMultiple()");
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = signatureServiceMultiple.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null);
            logger.info("Returning from extendDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } 
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @PostMapping(value = TIMESTAMP_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        try {
            logger.info("Entering timestampDocument()");
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            RemoteDocument ret = altSignatureService.timestamp(timestampDocumentDto.getDocument(), parameters);
            logger.info("Returning from timestampDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @PostMapping(value = TIMESTAMP_DOCUMENT_MULTIPLE, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocumentMultiple(@RequestBody TimestampDocumentMultipleDTO timestampDocumentDto) {
        try {
            logger.info("Entering timestampDocumentMultiple()");
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            RemoteDocument ret = signatureServiceMultiple.timestamp(timestampDocumentDto.getDocuments(), parameters);
            logger.info("Returning from timestampDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @PostMapping(value = GET_DATA_TO_SIGN_XADES_MULTI_DOC, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignXMLElementsDTO getDataToSignDto) {
        try {
            logger.info("Entering getDataToSignXades()");
            ClientSignatureParameters clientSigParams = getDataToSignDto.getClientSignatureParameters();
            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(getDataToSignDto.getSigningProfileId(), clientSigParams, getDataToSignDto.getPolicy());

            List<DSSReference> references = buildReferences(signingDate, getIdsToSign(getDataToSignDto.getElementsToSign()), parameters.getReferenceDigestAlgorithm());
            ToBeSignedDTO dataToSign = altSignatureService.getDataToSignWithReferences(getDataToSignDto.getToSignDocument(), parameters, references);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), signingDate);
            logger.info("Returning from getDataToSignXades()");
            return ret;
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

    /*****************************************************************************************/

    @PostMapping(value = SIGN_DOCUMENT_XADES_MULTI_DOC, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignXMLElementsDTO signDto) {
        try {
            logger.info("Entering signDocumentXades()");
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDto.getSigningProfileId(), clientSigParams, signDto.getPolicy());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());
            List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), getIdsToSign(signDto.getElementsToSign()), parameters.getReferenceDigestAlgorithm());
            RemoteDocument signedDoc = altSignatureService.signDocumentWithReferences(signDto.getToSignDocument(), parameters, signatureValueDto, references);

            signedDoc.setName(signDto.getToSignDocument().getName());
            logger.info("Returning from signDocumentXades()");
            return signedDoc;
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
}

/*****************************************************************************************/

