package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.*;
import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.utils.MediaTypeUtil;
import com.bosa.signandvalidation.utils.OCSPOnlyRevocationDataLoadingStrategy;
import com.bosa.signandvalidation.utils.OCSPOnlyForLeafRevocationDataLoadingStrategy;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.exception.NullParameterException;
import com.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.bosa.signingconfigurator.model.PolicyParameters;
import com.bosa.signingconfigurator.service.SigningConfiguratorService;
import com.bosa.signandvalidation.config.ErrorStrings;
import eu.europa.esig.dss.alert.exception.AlertException;
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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

import static com.bosa.signandvalidation.config.ThreadedCertificateVerifier.clearOverrideRevocationDataLoadingStrategyFactory;
import static com.bosa.signandvalidation.config.ThreadedCertificateVerifier.setOverrideRevocationDataLoadingStrategyFactory;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static com.bosa.signandvalidation.exceptions.Utils.checkAndRecordMDCToken;
import static com.bosa.signandvalidation.model.SigningType.XadesMultiFile;
import static com.bosa.signandvalidation.utils.XmlUtil.xmlDocToString;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import eu.europa.esig.dss.enumerations.Indication;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilder;
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
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


@Tag(name = "Electronic signature services", description = "See also https://github.com/Fedict/fts-documentation")
@RestController
@RequestMapping(value = SigningController.ENDPOINT)
public class SigningController extends ControllerBase implements ErrorStrings {

    protected final Logger logger = Logger.getLogger(SigningController.class.getName());

    // Service URL
    public static final String ENDPOINT                         = "/signing";

    public static final String PING                             = "/ping";
    public static final String VERSION                          = "/version";

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
    private static final String JSON_FILENAME_EXTENTION         = ".json";

    private static final SimpleDateFormat logDateTimeFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
    // Secret key cache
    private static final Cache<String, TokenObject> tokenCache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).build();

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
    private RemoteAltSignatureServiceImpl altSignatureService;

    @Autowired
    private StorageService storageService;

    @Autowired
    private Environment environment;

    @Value("${signing.time}")
    private Long signingTime;

    @Value("BOSA FTS v${application.version}")
    private String applicationName;

    @Value("${token.services}")
    private Boolean hasTokenServices;

    @Value("${signbox.services}")
    private Boolean hasSignBoxServices;

    @GetMapping(value = PING, produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    /*****************************************************************************************
     *
     * TOKEN Signing services
     *
     ****************************************************************************************/

    @Operation(summary = "Get a single document signing flow token", description = "Create signing flow, validate it's parameters and create a unique identifier")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token created and ready for use"),
            @ApiResponse(responseCode = "500", description = "Error while creating the token")
    })
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
            token.setNoSkipErrors(true);
            if (tokenData.getPolicyId() != null) {
                token.setPolicy(new PolicyParameters(tokenData.getPolicyId(), tokenData.getPolicyDescription(), tokenData.getPolicyDigestAlgorithm()));
            }
            token.setPreviewDocuments(true);
            token.setOutDownload(!tokenData.isNoDownload());
            token.setRequestDocumentReadConfirm(tokenData.isRequestDocumentReadConfirm());
            token.setSignTimeout(tokenData.getSignTimeout());
            if (tokenData.getAllowedToSign() != null) {
                List<String> nnAllowedToSign = new ArrayList<>();
                for(AllowedToSign allowedToSign : tokenData.getAllowedToSign()) {
                    nnAllowedToSign.add(allowedToSign.getNn());
                }
                token.setNnAllowedToSign(nnAllowedToSign);
            }

            checkTokenAndSetDefaults(token);

            String tokenString = saveToken(token);
            checkAndRecordMDCToken(tokenString);
            logger.info("Returning from getTokenForDocument() params: " + objectToString(tokenData));
            return tokenString;
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Create a 'signing flow token' for 1 to N documents ", description = "Create signing flow, validate it's parameters and create a unique identifier (Token).<BR>" +
            "This token must be provided in the redirection URL to the BOSA DSS front-end server" +
            "This is the new operation for token creation, future evolutions of the service will only be done on this operation.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token created and ready for use"),
            @ApiResponse(responseCode = "500", description = "Error while creating the token")
    })
    @PostMapping(value = GET_TOKEN_FOR_DOCUMENTS, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocuments(@RequestBody GetTokenForDocumentsDTO gtfd) {
        authorizeCall(hasTokenServices);

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
        String tokenString = saveToken(token);
        checkAndRecordMDCToken(tokenString);
        logger.info("Returning from getTokenForDocuments() params: " + objectToString(gtfd));
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
            String profileId = token.getXmlSignProfile();
            if (profileId == null || !profileId.startsWith("MDOC_XADES_LTA")) {
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

    @Operation(hidden = true)
    @GetMapping(value = GET_METADATA_FOR_TOKEN)
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String tokenString) {
        authorizeCall(hasTokenServices);
        try {
            checkAndRecordMDCToken(tokenString);
            logger.info("Entering getMetadataForToken()");

            TokenObject token = getTokenFromId(tokenString);
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

            logger.info("Returning from getMetadataForToken()");
            return new DocumentMetadataDTO(token.getSigningType(), getPhoto, !token.isOutDownload(),
                    token.isSelectDocuments(), token.isRequestDocumentReadConfirm(), token.isPreviewDocuments(), token.isNoSkipErrors(), signedInputsMetadata);
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

    @Operation(hidden = true)
    @GetMapping(value = GET_FILE_FOR_TOKEN + "/{token}/{type}/{inputIndexes}")
    public void getFileForToken(@PathVariable("token") String tokenString,
                                @PathVariable GetFileType type,
                                @PathVariable(required = true) Integer inputIndexes[],
                                @RequestParam(required = false)  String forceDownload,
                                HttpServletResponse response) {

        authorizeCall(hasTokenServices);
        ZipOutputStream out = null;
        InputStream fileStream = null;
        try {
            checkAndRecordMDCToken(tokenString);
            logger.info("Entering getFileForToken()");

            TokenObject token = getTokenFromId(tokenString);

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
                    if (token.isOutDownload()) {
                        if (token.getSigningType().equals(XadesMultiFile) || inputIndexes.length == 1) singleFilePath = getOutFilePath(token, input);
                        break;
                    }

                default:
                    logAndThrowEx(tokenString, BAD_REQUEST, BLOCKED_DOWNLOAD, "Forging request attempt !");
            }

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
            logger.info("Returning from getFileForToken()");
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

    @Operation(hidden = true)
    @PostMapping(value = GET_DATA_TO_SIGN_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        authorizeCall(hasTokenServices);
        try {
            checkAndRecordMDCToken(dataToSignForTokenDto.getToken());
            logger.info("Entering getDataToSignForToken()");

            TokenObject token = getTokenFromId(dataToSignForTokenDto.getToken());
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
            ProfileSignatureParameters signProfile = null;
            if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
                String profileId = token.getXmlSignProfile();
                if (profileId == null) {
                    // Double check that profile is not NULL to avoid default being used
                    logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, "Profile is null, aborting !");
                }
                signProfile = signingConfigService.findProfileParamsById(profileId);
                parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
                List<String> idsToSign = new ArrayList<String>(token.getInputs().size());
                for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
                references = buildReferences(signingDate, idsToSign, parameters.getReferenceDigestAlgorithm());
                filePath = token.getOutFilePath();
            } else {
                inputToSign = token.getInputs().get(dataToSignForTokenDto.getFileIdToSign());
                filePath = inputToSign.getFilePath();
                mediaType = MediaTypeUtil.getMediaTypeFromFilename(filePath);
                String profileId = APPLICATION_PDF.equals(mediaType) ? token.getPdfSignProfile() : token.getXmlSignProfile();
                if (profileId == null) {
                    // Double check that profile is not NULL to avoid default being used
                    logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, "Profile is null, aborting !");
                }
                signProfile = signingConfigService.findProfileParamsById(profileId);
                parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
            }

            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, null);

            checkDataToSign(parameters, dataToSignForTokenDto.getToken());

            if (APPLICATION_PDF.equals(mediaType)) {
                pdfVisibleSignatureService.checkAndFillParams(parameters, fileToSign, inputToSign, token.getBucket(), clientSigParams);
            }

            ToBeSignedDTO dataToSign = altSignatureService.altGetDataToSign(fileToSign, parameters, references, applicationName);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), clientSigParams.getSigningDate());

            logger.info("Returning from getDataToSignForToken()");

            return ret;
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch (AlertException e) {
            String message = e.getMessage();
            if (message == null || !message.startsWith("The new signature field position is outside the page dimensions!")) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
            }
            logAndThrowEx(INTERNAL_SERVER_ERROR, SIGNATURE_OUT_OF_BOUNDS, e);
        } catch (Exception e) {
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(hidden = true)
    @PostMapping(value = SIGN_DOCUMENT_FOR_TOKEN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<RemoteDocument> signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDto) {
        authorizeCall(hasTokenServices);
        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentForToken()");

            TokenObject token = getTokenFromId(signDto.getToken());
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
            ProfileSignatureParameters signProfile = null;
            if (SigningType.XadesMultiFile.equals(token.getSigningType())) {
                signProfile = signingConfigService.findProfileParamsById(token.getXmlSignProfile());
                parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
                List<String> idsToSign = new ArrayList<String>(token.getInputs().size());
                for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
                references = buildReferences(clientSigParams.getSigningDate(), idsToSign, parameters.getReferenceDigestAlgorithm());
                filePath = token.getOutFilePath();
            } else {
                inputToSign = token.getInputs().get(signDto.getFileIdToSign());
                filePath = inputToSign.getFilePath();
                mediaType = MediaTypeUtil.getMediaTypeFromFilename(filePath);
                String signProfileId = APPLICATION_PDF.equals(mediaType) ? token.getPdfSignProfile() : token.getXmlSignProfile();
                signProfile = signingConfigService.findProfileParamsById(signProfileId);
                parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
            }

            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
            RemoteDocument fileToSign = new RemoteDocument(bytesToSign, null);
            if (APPLICATION_PDF.equals(mediaType)) {
                pdfVisibleSignatureService.checkAndFillParams(parameters, fileToSign, inputToSign, token.getBucket(), clientSigParams);
            }

            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(fileToSign, parameters, signatureValueDto, references, applicationName);

            if (signProfile.getAddCertPathToKeyinfo()) addCertPathToKeyinfo(signedDoc, clientSigParams);

            signedDoc.setName(getOutFilePath(token, inputToSign));

            logger.info("signDocumentForToken(): validating the signed doc");

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            List<RemoteDocument> detachedDocuments = clientSigParams.getDetachedContents();
            if (detachedDocuments == null) detachedDocuments = new ArrayList<>();
            detachedDocuments.add(fileToSign);

            signedDoc = validateResult(signedDoc, detachedDocuments, parameters, token, signedDoc.getName(), null);

            // Save signed file
            storageService.storeFile(token.getBucket(), signedDoc.getName(), signedDoc.getBytes());

            // Log bucket and filename only for this method
            MDC.put("bucket", token.getBucket());
            MDC.put("fileName", signedDoc.getName());
            logger.info("Returning from signDocumentForToken().");
            MDC.remove("bucket");
            MDC.remove("fileName");

            logger.info("Returning from signDocumentForToken()");
        } catch (Exception e) {
            handleRevokedCertificates(e);
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }

        return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);
    }

    /*****************************************************************************************/

    // For the Justice dept the signature must contain the Full cert path in the KeyInfo element even for all XADES signatures
    // For LT/LTA signatures, EIDAS states that the certs must be present in "CertificateValues/EncapsulatedX509Certificate" but can
    // also be present in the KeyInfo element. DSS does not put the Root cert in the KeyInfo for LT/LTA

    private void addCertPathToKeyinfo(RemoteDocument signedDoc, ClientSignatureParameters clientSigParams) throws ParserConfigurationException, TransformerException, IOException, SAXException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(signedDoc.getBytes()));

        logger.info(xmlDocToString(doc));

        NodeList elements = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Data");
        if (elements == null || elements.getLength() != 1) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INVALID_DOC, "Can't find X509Data to add Root CERT");
        }

        Node x509Data = elements.item(0);
        if (x509Data.getParentNode() == null || "KeyInfo".compareTo(x509Data.getParentNode().getLocalName()) != 0) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INVALID_DOC, "X509Data not enclosed KeyInfo");
        }

        List<String> certsToAdd = new ArrayList<>();
        for(RemoteCertificate cert : clientSigParams.getCertificateChain()) {
            String certBase64 = Base64.getEncoder().encodeToString(cert.getEncodedCertificate());
            Node x509Cert = x509Data.getFirstChild();
            while(true) {
                if (x509Cert == null) {
                    certsToAdd.add(certBase64);
                    break;
                }
                if (certBase64.equals(x509Cert.getTextContent())) break;
                x509Cert = x509Cert.getNextSibling();
            }
        }

        if (certsToAdd.isEmpty()) return;

        for(String certToAdd : certsToAdd) {
            Node x509Cert = doc.createElementNS( "http://www.w3.org/2000/09/xmldsig#", "ds:X509Certificate");
            x509Cert.setTextContent(certToAdd);
            x509Data.appendChild(x509Cert);
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        tf.newTransformer().transform(new DOMSource(doc), new StreamResult(bos));
        signedDoc.setBytes(bos.toByteArray());
    }

    /*****************************************************************************************/

    // This mechanism allow dynamic control over the CertificateVerifier for the RevocationDataLoadingStrategyFactory
    // based on the signProfile "revocationStrategy" attribute
    private void setOverrideRevocationStrategy(ProfileSignatureParameters signProfile) {
        switch(signProfile.getRevocationStrategy()) {
            case OCSP_ONLY:
                setOverrideRevocationDataLoadingStrategyFactory(OCSPOnlyRevocationDataLoadingStrategy::new);
                break;
            case OCSP_ONLY_FOR_LEAF:
                setOverrideRevocationDataLoadingStrategyFactory(OCSPOnlyForLeafRevocationDataLoadingStrategy::new);

            case DEFAULT:
                break;
        }
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
        SignatureFullValiationDTO reportsDto = validationService.validateDocument(signedDoc, detachedContents, validatePolicy, null, parameters);

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
    // Save token object to storageService and return a tokenId

    String saveToken(TokenObject token)  {
        String tokenId = null;
        try {
            token.setCreateTime(new Date().getTime());

            byte[] tokenBytes = new byte[12];
            new SecureRandom().nextBytes(tokenBytes);
            tokenId = Base64.getUrlEncoder().encodeToString(tokenBytes);

            // Store token in secret bucket
            ObjectMapper om = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);
            storageService.storeFile(null, KEYS_FOLDER + tokenId + JSON_FILENAME_EXTENTION, om.writeValueAsBytes(token));

            // Cache token
            tokenCache.put(tokenId, token);
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return tokenId;
    }

    /*****************************************************************************************/

    // Get token from cache or storageService
    private TokenObject getTokenFromId(String tokenId) {
        TokenObject token = null;
        try {

            token = tokenCache.getIfPresent(tokenId);
            if (token == null) {
                byte[] rawToken = storageService.getFileAsBytes(null, KEYS_FOLDER + tokenId + JSON_FILENAME_EXTENTION, false);
                token = new ObjectMapper().readValue(rawToken, TokenObject.class);
                tokenCache.put(tokenId, token);
            }

            if (new Date().getTime() > (token.getCreateTime() + token.getTokenTimeout() * 1000L)) {
                logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, "Token is expired");
            }
        } catch(IOException | IllegalArgumentException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_TOKEN, e);
        }
        return token;
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

    @Operation(summary = "Calculate the digest of a file to sign", description = "Calculate the digest of a file to sign.<BR>" +
            "This is the first step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = DataToSignDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter | Invalid PDF signature parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = GET_DATA_TO_SIGN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(dataToSignDto.getToken());
            logger.info("Entering getDataToSign()");

            ClientSignatureParameters clientSigParams = dataToSignDto.getClientSignatureParameters();
            clientSigParams.setSigningDate(new Date());
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(dataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);

            setOverrideRevocationStrategy(signProfile);

            checkDataToSign(parameters, null);

            pdfVisibleSignatureService.checkAndFillParams(parameters, dataToSignDto.getToSignDocument(), clientSigParams);

            ToBeSignedDTO dataToSign = altSignatureService.altGetDataToSign(dataToSignDto.getToSignDocument(), parameters, null, applicationName);

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            byte [] bytesToSign = dataToSign.getBytes();
            if (!signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, bytesToSign, dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSign()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Calculate the digest of a list of files to sign", description = "Calculate the digest of a list of files to sign.<BR>" +
            "This is the first step in a two step process to sign the files")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = DataToSignDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/getDataToSignMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignMultiple(@RequestBody GetDataToSignMultipleDTO dataToSignDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(dataToSignDto.getToken());
            logger.info("Entering getDataToSignMultiple()");

            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(dataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, dataToSignDto.getClientSignatureParameters(), null);

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()), dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSignMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create the signed file based on the signed digest.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(signDocumentDto.getToken());
            logger.info("Entering signDocument()");

            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDocumentDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);
            setOverrideRevocationStrategy(signProfile);

            pdfVisibleSignatureService.checkAndFillParams(parameters, signDocumentDto.getToSignDocument(), clientSigParams);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(signDocumentDto.getToSignDocument(), parameters, signatureValueDto, null, applicationName);

            if (signProfile.getAddCertPathToKeyinfo()) addCertPathToKeyinfo(signedDoc, clientSigParams);

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            List<RemoteDocument> detachedDocuments = clientSigParams.getDetachedContents();
            if (detachedDocuments == null) detachedDocuments = new ArrayList<>();
            detachedDocuments.add(signDocumentDto.getToSignDocument());

            RemoteDocument ret =  validateResult(signedDoc, detachedDocuments, parameters, signDocumentDto.getValidatePolicy());
            logger.info("Returning from signDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException | ParserConfigurationException | TransformerException | SAXException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Create the signed file based on the signed digest", description = "Create a signed file based on the signed digest of a list of files.<BR>" +
            "This is the first step in a two step process to sign the file<BR>" +
            "The signed result will be of the ASIC format<BR>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = "/signDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentMultiple(@RequestBody SignDocumentMultipleDTO signDocumentDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(signDocumentDto.getToken());
            logger.info("Entering signDocumentMultiple()");

            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDocumentDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);
            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDocumentDto.getToSignDocuments(), parameters, signatureValueDto);

            if (signProfile.getAddCertPathToKeyinfo()) addCertPathToKeyinfo(signedDoc, clientSigParams);

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            RemoteDocument ret = validateResult(signedDoc, signDocumentDto.getToSignDocuments(), parameters, signDocumentDto.getValidatePolicy());
            logger.info("Returning from signDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException | ParserConfigurationException | TransformerException | SAXException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Extend the signature of a list of files", description = "Based on an existing signature, raise its signature level by adding the 'long term' attributes (OCSP/CRL evidences) or timestamps")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_MULTIPLE, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocumentMultiple(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(extendDocumentDto.getToken());
            logger.info("Entering extendDocumentMultiple()");

            ProfileSignatureParameters extendProfile = signingConfigService.findProfileParamsById(extendDocumentDto.getExtendProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendProfile, extendDocumentDto.getDetachedContents());
            setOverrideRevocationStrategy(extendProfile);

            RemoteDocument extendedDoc = signatureServiceMultiple.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null);
            logger.info("Returning from extendDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Extend the signature of a file", description = "Based on a pre-signed file, raise its signature level by adding the 'long term' attributes (OCSP/CRL evidences) or timestamps")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(extendDocumentDto.getToken());
            logger.info("Entering extendDocument()");

            ProfileSignatureParameters extendProfile = signingConfigService.findProfileParamsById(extendDocumentDto.getExtendProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendProfile, extendDocumentDto.getDetachedContents());
            setOverrideRevocationStrategy(extendProfile);

            RemoteDocument extendedDoc = altSignatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null);
            logger.info("Returning from extendDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Timestamp a file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = TIMESTAMP_DOCUMENT, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(timestampDocumentDto.getToken());
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

    @Operation(summary = "Timestamp a list of files and produce a file in ASIC format")
    @PostMapping(value = TIMESTAMP_DOCUMENT_MULTIPLE, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocumentMultiple(@RequestBody TimestampDocumentMultipleDTO timestampDocumentDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(timestampDocumentDto.getToken());
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

    @Operation(summary = "Calculate the digest of a file to sign as Xades Internally detached", description = "Calculate the digest of a file to sign as Xades Internally detached.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = DataToSignDTO.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter | Invalid PDF signature parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = GET_DATA_TO_SIGN_XADES_MULTI_DOC, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignXMLElementsDTO getDataToSignDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(getDataToSignDto.getToken());
            logger.info("Entering getDataToSignXades()");

            ClientSignatureParameters clientSigParams = getDataToSignDto.getClientSignatureParameters();
            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(getDataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, policyDtoToPolicyParameters(getDataToSignDto.getPolicy()));

            List<DSSReference> references = buildReferences(signingDate, getDataToSignDto.getElementIdsToSign(), parameters.getReferenceDigestAlgorithm());

            ToBeSignedDTO dataToSign = altSignatureService.altGetDataToSign(getDataToSignDto.getToSignDocument(), parameters, references, null);
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
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    /*****************************************************************************************/

    @Operation(summary = "Create the signed file as Xades Internally detached based on the signed digest", description = "Create the signed file as Xades Internally detached based on the signed digest.<BR>" +
            "This is the second step in a two step process to sign the file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile | Empty mandatory parameter",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = SIGN_DOCUMENT_XADES_MULTI_DOC, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignXMLElementsDTO signDto) {
        authorizeCall(hasSignBoxServices);
        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentXades()");

            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDto.getSigningProfileId());
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, policyDtoToPolicyParameters(signDto.getPolicy()));
            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDto.getSignatureValue());
            List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), signDto.getElementIdsToSign(), parameters.getReferenceDigestAlgorithm());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(signDto.getToSignDocument(), parameters, signatureValueDto, references, null);

            if (signProfile.getAddCertPathToKeyinfo()) addCertPathToKeyinfo(signedDoc, clientSigParams);

            signedDoc.setName(signDto.getToSignDocument().getName());
            logger.info("Returning from signDocumentXades()");
            return signedDoc;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException | ParserConfigurationException | TransformerException | SAXException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } finally {
            clearOverrideRevocationDataLoadingStrategyFactory();
        }
        return null; // We won't get here
    }

/*****************************************************************************************/

    private static PolicyParameters policyDtoToPolicyParameters(PolicyDTO dto) {
        return new PolicyParameters(dto.getId(), dto.getDescription(), dto.getDigestAlgorithm());
    }

/*****************************************************************************************/

public static void authorizeCall(Boolean authorize) {
    if (!authorize) throw new InvalidParameterException("Unknown Operation");
}

/*****************************************************************************************/

private static void handleRevokedCertificates(Exception e) {
    if (e instanceof AlertException && e.getMessage().startsWith("Revoked/Suspended certificate")) {
        logAndThrowEx(BAD_REQUEST, CERT_REVOKED, e);
    }
}

/*****************************************************************************************/
}
