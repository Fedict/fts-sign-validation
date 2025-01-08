package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.service.*;
import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.utils.MediaTypeUtil;
import com.bosa.signandvalidation.utils.OCSPOnlyRevocationDataLoadingStrategy;
import com.bosa.signandvalidation.utils.OCSPOnlyForLeafRevocationDataLoadingStrategy;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.VisiblePdfSignatureParameters;
import com.fasterxml.jackson.annotation.JsonInclude;
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
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.enumerations.SignatureForm;
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
import eu.europa.esig.dss.xml.common.DocumentBuilderFactoryBuilder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.xml.security.transforms.Transforms;
import org.jetbrains.annotations.NotNull;
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

import static com.bosa.signandvalidation.config.ThreadedCertificateVerifier.setOverrideRevocationDataLoadingStrategyFactory;
import static com.bosa.signandvalidation.exceptions.Utils.*;
import static com.bosa.signandvalidation.model.SigningType.*;
import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.DEFAULT_STRING;
import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.TRANSPARENT;
import static com.bosa.signandvalidation.utils.SupportUtils.longToBytes;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.xml.XMLConstants;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
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

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LT;
import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LTA;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.*;

import org.springframework.http.ResponseEntity;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


@Tag(name = "Electronic signature services", description = "See also https://github.com/Fedict/fts-documentation")
@RestController
@RequestMapping(value = SigningController.ENDPOINT_URL)
public class SigningController extends ControllerBase implements ErrorStrings {

    protected final Logger logger = Logger.getLogger(SigningController.class.getName());

    // Service URL
    public static final String ENDPOINT_URL                     = "/signing";

    public static final String LOGGING_URL                      = "/log";
    public static final String PING_URL                         = "/ping";
    public static final String ERROR_URL                        = "/error";
    public static final String VERSION_URL                      = "/versions";

    // Token operations
    public static final String GET_TOKEN_FOR_DOCUMENT_URL       = "/getTokenForDocument";
    public static final String GET_TOKEN_FOR_DOCUMENTS_URL      = "/getTokenForDocuments";
    public static final String GET_DATA_TO_SIGN_FOR_TOKEN_URL   = "/getDataToSignForToken";
    public static final String GET_METADATA_FOR_TOKEN_URL       = "/getMetadataForToken";
    public static final String GET_FILE_FOR_TOKEN_URL           = "/getFileForToken";
    public static final String SIGN_DOCUMENT_FOR_TOKEN_URL      = "/signDocumentsForToken";

    // standard operations
    public static final String GET_DATA_TO_SIGN_URL             = "/getDataToSign";
    public static final String SIGN_DOCUMENT_URL                = "/signDocument";
    public static final String EXTEND_DOCUMENT_URL              = "/extendDocument";
    public static final String EXTEND_DOCUMENT_MULTIPLE_URL     = "/extendDocumentMultiple";
    public static final String TIMESTAMP_DOCUMENT_URL           = "/timestampDocument";
    public static final String TIMESTAMP_DOCUMENT_MULTIPLE_URL  = "/timestampDocumentMultiple";
    public static final String GET_DATA_TO_SIGN_XADES_MDOC_URL  = "/getDataToSignXades";
    public static final String SIGN_DOCUMENT_XADES_MDOC_URL     = "/signDocumentXades";

    private static final int SIZE_TOKEN_ID                      = 12;
    public static final int DEFAULT_SIGN_DURATION_SECS              = 2 * 60;
    public static final int MAX_NN_ALLOWED_TO_SIGN                  = 32;
    private static final Pattern nnPattern                          = Pattern.compile("[0-9]{11}");
    private static final Pattern eltIdPattern                       = Pattern.compile("[a-zA-Z0-9\\-_]{1,30}");
    private static final Pattern pspColorPattern                    = Pattern.compile("(#[0-9a-fA-F]{6}|" + TRANSPARENT + ")");
    private static final Pattern pspFontPattern                     = Pattern.compile(".*(/b|/i|/bi|/ib)?"); // <FontName>/<b><i>. Sample : "Serif/bi"

    public static final String KEYS_FOLDER                      = "keys/";
    private static final String JSON_FILENAME_EXTENSION         = ".json";

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

    // Token timeout is 5 hours (300 minutes) or else
    @Value("${token.timeout:300}")
    private Integer defaultTokenTimeout;

    @Value("${signing.time}")
    private Long signingTime;

    @Value("BOSA FTS v${application.version}")
    private String applicationName;

    @Value("${features}")
    private String features;

    private final SecureRandom secureRandom = new SecureRandom();

    @GetMapping(value = PING_URL, produces = TEXT_PLAIN_VALUE)
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
    @PostMapping(value = GET_TOKEN_FOR_DOCUMENT_URL, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocument(@RequestBody GetTokenForDocumentDTO tokenData) {
        try {
            authorizeCall(features, Features.token);
            if(!(storageService.isValidAuth(tokenData.getName(), tokenData.getPwd()))) {
                logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
            }
            // Password not needed anymore (Avoid MDC logging)
            tokenData.setPwd(null);

            TokenObject token = new TokenObject();
            token.setSigningType(SigningType.Standard);
            token.setBucket(tokenData.getName());
            token.setOutFilePath(tokenData.getOut());
            String profileId = tokenData.getProf();
            if (profileId != null && profileId.isEmpty()) profileId = null;
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(profileId);
            if (signProfile != null) {
                if (SignatureForm.XAdES.equals(signProfile.getSignatureForm())) token.setXmlSignProfile(profileId);
                else if (SignatureForm.PAdES.equals(signProfile.getSignatureForm())) token.setPdfSignProfile(profileId);
            }
            List<TokenSignInput> inputs = new ArrayList<>();
            TokenSignInput input = new TokenSignInput();
            input.setFilePath(tokenData.getIn());
            input.setSignLanguage(tokenData.getLang());
            input.setPspFilePath(tokenData.getPsp());
            input.setPsfP(Boolean.parseBoolean(tokenData.getPsfP()));
            input.setPsfC(tokenData.getPsfC());
            input.setPsfN(tokenData.getPsfN());
            input.setDisplayXsltPath(tokenData.getXslt());
            input.setInvisible(true);
            inputs.add(input);
            token.setInputs(inputs);
            token.setNoSkipErrors(true);
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
            MDC.put("token", tokenString);
            objectToMDC(tokenData);
            logger.info("Returning from getTokenForDocument()");
            return tokenString;
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Operation(summary = "Create a 'signing flow token' for 1 to N documents ", description = "Create signing flow, validate it's parameters and create a unique identifier (Token).<BR>" +
            "This token must be provided in the redirection URL to the BOSA DSS front-end server" +
            "This is the new operation for token creation, future evolutions of the service will only be done on this operation.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token created and ready for use"),
            @ApiResponse(responseCode = "500", description = "Error while creating the token")
    })
    @PostMapping(value = GET_TOKEN_FOR_DOCUMENTS_URL, produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocuments(@RequestBody GetTokenForDocumentsDTO gtfd) throws IllegalAccessException {
        try {
            authorizeCall(features, Features.token);

            // Validate input
            if(!(storageService.isValidAuth(gtfd.getBucket(), gtfd.getPassword()))) {
                logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
            }
            // Password not needed anymore (Avoid MDC logging)
            gtfd.setPassword(null);

            TokenObject token = new TokenObject();
            token.setBucket(gtfd.getBucket());
            token.setInputs(getTokenSignInputs(gtfd));
            token.setOutFilePath(gtfd.getOutFilePath());
            setProfileInfo(token, gtfd.getSignProfile());
            setProfileInfo(token, gtfd.getAltSignProfile());
            token.setSignTimeout(gtfd.getSignTimeout());
            token.setNnAllowedToSign(gtfd.getNnAllowedToSign());
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
            MDC.put("token", tokenString);
            objectToMDC(gtfd);
            logger.info("Returning from getTokenForDocuments()");
            return tokenString;
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null;
    }

    //*****************************************************************************************

    @NotNull
    private static List<TokenSignInput> getTokenSignInputs(GetTokenForDocumentsDTO gtfd) {
        List<TokenSignInput> tokenInputs = new ArrayList<>();
        for(SignInput input : gtfd.getInputs()) {
            TokenSignInput ti = new TokenSignInput();
            ti.setFilePath(input.getFilePath());
            ti.setXmlEltId(input.getXmlEltId());
            ti.setDisplayXsltPath(input.getDisplayXsltPath());
            ti.setPspFilePath(input.getPspFilePath());
            ti.setSignLanguage(input.getSignLanguage());
            ti.setDocumentURI(input.getFileURI());
            ti.setPsfC(input.getPsfC());
            ti.setPsfN(input.getPsfN());
            ti.setPsfP(input.isPsfP());
            Boolean drawable = input.getDrawable();
            ti.setInvisible(drawable == null || !drawable);
            tokenInputs.add(ti);
        }
        return tokenInputs;
    }

    //*****************************************************************************************

    // Convoluted logic to identify if we have one or two profiles, for xml files and/or pdf files
    private void setProfileInfo(TokenObject token, String profileId) {
        if (profileId == null || profileId.isEmpty()) return;
        ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(profileId);
        if (signProfile == null) {
            logAndThrowEx(FORBIDDEN, INVALID_PARAM, "signProfile is invalid." , null);
        }
        if (SignatureForm.PAdES.equals(signProfile.getSignatureForm())) {
            if (token.getPdfSignProfile() != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "signProfile and altSignProfile must be for different file types." , null);
            }
            token.setPdfSignProfile(profileId);
        }
        else if (SignatureForm.XAdES.equals(signProfile.getSignatureForm())) {
            if (token.getXmlSignProfile() != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "signProfile and altSignProfile must be for different file types." , null);
            }
            token.setXmlSignProfile(profileId);
        }

        SigningType signingType = token.getSigningType();
        if (signingType != null) {
            if (signingType != signProfile.getSigningType()) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "signProfile and altSignProfile must be of the same signingType ('" + signingType + "' != '" +signProfile.getSigningType() + "')." , null);
            }
        }
        token.setSigningType(signProfile.getSigningType());
    }

    //*****************************************************************************************

    private void checkTokenAndSetDefaults(TokenObject token) throws Exception {

        // Validate token input values
        validateTokenValues(token);

        if (XadesMultiFile.equals(token.getSigningType())) return;

        // Validate visible signature parameters
        for(TokenSignInput input : token.getInputs()) {
            MediaType inputFileType = MediaTypeUtil.getMediaTypeFromFilename(input.getFilePath());
            if (!APPLICATION_PDF.equals(inputFileType)) continue;

            String psfC = input.getPsfC();
            String psfN = input.getPsfN();
            if (psfN == null && psfC == null) continue;

            byte[] file = storageService.getFileAsBytes(token.getBucket(), input.getFilePath(), true);
            PDDocument pdfDoc = PDDocument.load(new ByteArrayInputStream(file), (String) null);
            PdfSignatureProfile psp = getPspFile(input, token.getBucket());
            PDRectangle rect = checkVisibleSignatureParameters(psfC, psfN, psp, pdfDoc);
            if (rect != null) {
                // Save for later phases to avoid re-loading the PDF
                input.setPsfNHeight(rect.getHeight());
                input.setPsfNWidth(rect.getWidth());
            }
            pdfDoc.close();
        }
    }

    //*****************************************************************************************

    // In order to keep coherence between token and non-toke operations the validation code is the same
    static PDRectangle checkVisibleSignatureParameters(String psfC, String psfN, PdfSignatureProfile psp, PDDocument pdfDoc) {
        // Check psfN
        if (psfN != null) {
            try {
                List<PDSignatureField> sigFields = pdfDoc.getSignatureFields();
                for (PDSignatureField sigField : sigFields) {
                    String name = sigField.getPartialName();
                    if (psfN.equals(name)) {
                        if (sigField.getSignature() != null) {
                            logAndThrowEx(FORBIDDEN, INVALID_PARAM, "The specified PDF signature field already contains a signature.", null);
                        }
                        return sigField.getWidget().getRectangle();
                    }
                }
            } catch (IOException e) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Error reading PDF file.", null);
            }
            logAndThrowEx(FORBIDDEN, INVALID_PARAM, "The PDF signature field does exist : " + psfN, null);
        }

        // Check psfC
        if (DEFAULT_STRING.equals(psfC) && psp != null) psfC = psp.defaultCoordinates;
        if (psfC == null) logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Default PDF signature coordinates requested, but these were not specified in the psp (or no psp)", null);
        checkPsfC(pdfDoc, psfC);

        if (psp != null) {
            // Check if all date formats are accepted
            Date now = new Date();
            for(String text : psp.texts.values()) PdfVisibleSignatureService.injectDate(text, now, "en");

            checkPspColor(psp.bgColor, "bgColor");
            if (psp.font != null && !pspFontPattern.matcher(psp.font).matches()) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "PSP font '" + psp.font + "' does not match Regex (" + pspFontPattern.pattern() + ")" , null);
            }
            checkPspColor(psp.textColor, "textColor");
            if (psp.version != null && psp.version != 1 && psp.version != 2) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "PSP version invalid : " + psp.version, null);
            }
            checkPspColor(psp.bodyBgColor, "bodyBgColor");
        }

        return null;
    }

    //*****************************************************************************************

    private static void checkPspColor(String color, String name) {
        if (color != null && !pspColorPattern.matcher(color).matches()) {
            logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'" + name + "' (" + color + ") does not match Regex (" + pspColorPattern.pattern() + ")" , null);
        }
    }

    //*****************************************************************************************

    static void checkPsfC(PDDocument pdfDoc, String psfC) {
        int fieldNb = 5;
        String[] coords = psfC.split(",");
        if (coords.length == fieldNb) {
            float[] boxCoords = new float[fieldNb];
            try {
                while (fieldNb != 0) boxCoords[--fieldNb] = Float.parseFloat(coords[fieldNb]);
                try {
                    PDPage page = pdfDoc.getPage((int)boxCoords[0] - 1);
                    PDRectangle box = page.getBBox();
                    if (page.getRotation() == 90 ?
                            (!box.contains(boxCoords[2], boxCoords[1]) || !box.contains(boxCoords[2] + boxCoords[4], boxCoords[1] + boxCoords[3])) :
                            (!box.contains(boxCoords[1], boxCoords[2]) || !box.contains(boxCoords[1] + boxCoords[3], boxCoords[2] + boxCoords[4]))) {
                        logAndThrowEx(FORBIDDEN, SIGNATURE_OUT_OF_BOUNDS, "The new signature field position is outside the page dimensions: '" + psfC + "'", null);
                    }
                    return;
                } catch (IndexOutOfBoundsException e) {
                    logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Invalid PDF signature page: '" + psfC + "'", null);
                }
            } catch(NumberFormatException e) {}
        }
        logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Invalid PDF signature coordinates: '" + psfC + "'", null);
    }

    //*****************************************************************************************

    void validateTokenValues(TokenObject token) {

        SigningType signingType = token.getSigningType();
        String pdfProfileId = token.getPdfSignProfile();
        String xmlProfileId = token.getXmlSignProfile();

        Integer tokenTimeout = token.getTokenTimeout();
        if (defaultTokenTimeout == null) defaultTokenTimeout = 300;
        if (tokenTimeout == null) token.setTokenTimeout(tokenTimeout = defaultTokenTimeout * 60);

        Integer signTimeout = token.getSignTimeout();
        if (signTimeout == null) token.setSignTimeout(signTimeout = DEFAULT_SIGN_DURATION_SECS);
        if (signTimeout > tokenTimeout) {
            logAndThrowEx(FORBIDDEN, INVALID_PARAM, "signTimeout (" + signTimeout + ") can't be larger than  Token expiration (" + tokenTimeout + ")" , null);
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
        if (inputs == null || inputs.isEmpty()) {
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

            switch(signingType) {
                case XadesMultiFile:
                    checkValue("XmlEltId", input.getXmlEltId(), false, eltIdPattern, eltIdList);
                    if (input.getPsfN() != null || input.getPsfC() != null || input.getSignLanguage() != null || input.getPspFilePath() != null) {
                        logAndThrowEx(FORBIDDEN, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for " + signingType, null);
                    }
                    break;

                case MultiFileDetached:
                    if (input.getXmlEltId() != null || input.getPsfN() != null || input.getPsfC() != null || input.getSignLanguage() != null || input.getPspFilePath() != null) {

                        logAndThrowEx(FORBIDDEN, INVALID_PARAM, "XmlEltId, PsfN, PsfC, SignLanguage and PspFileName must be null for " + signingType, null);
                    }
                   break;

                default:
                    if (input.getXmlEltId() != null) {
                        logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'XmlEltId' must be null for " + signingType, null);
                    }

                    if ((isPDF && pdfProfileId == null) || (isXML && xmlProfileId == null)) {
                        logAndThrowEx(FORBIDDEN, INVALID_PARAM, "No signProfile for file type provided (" + inputFileType + " => " + pdfProfileId + "/" + xmlProfileId + ")", null);
                    }
                    break;
            }
            if (!isXML && input.getDisplayXsltPath() != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "DisplayXslt must be null for non-xml files", null);
            }
        }

        String prefix = token.getOutPathPrefix();
        if (signingType == XadesMultiFile) {
            if (pdfProfileId != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "XadesMultiFile must be used only for XML files", null);
            }
            checkValue("outXsltPath", token.getOutXsltPath(), true, null, filenamesList);
        } else {
            if (token.getOutXsltPath() != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outXsltPath' must be null for " + signingType, null);
            }
        }
        if (signingType == Standard) {
            if (inputs.size() > 1 && !token.isPreviewDocuments()) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "previewDocuments must be 'true' for Standard", null);
            }
        } else {
            if (prefix != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outPathPrefix' must be null for " + signingType, null);
            }
            if (token.isSelectDocuments()) {
                // Non 'Standard' signTypes sign all files at the same time so can't have "cherry picked" files without large changes
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Can't individually select documents for " + signingType, null);
            }
        }

        String outPath = token.getOutFilePath();
        if (outPath != null && outPath.isEmpty()) token.setOutFilePath(outPath = null);

        if (prefix != null) {
            if (prefix.endsWith("/")) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outPathPrefix' can't end with '/'", null);
            }

            if (outPath != null) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'outFilePath' must be null if outPathPrefix is set (Bulk Signing)", null);
            }
        } else {
            checkValue("outFilePath", outPath, false, null, filenamesList);
        }
    }

    //*****************************************************************************************

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

    //*****************************************************************************************

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

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();   // No risk for XXE as we're building this XML from scratch
            dbf.setNamespaceAware(true);
            JAXBContext context = JAXBContext.newInstance(XadesFileRoot.class);

            Document doc = dbf.newDocumentBuilder().newDocument();
            context.createMarshaller().marshal(root, doc);

            //logger.info(xmlDocToString(doc));

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

                //logger.info(xmlDocToString(doc));
            }

            putFilesContent(doc.getFirstChild(), token);

            //logger.info(xmlDocToString(doc));

            // Save target XML to bucket
            ByteArrayOutputStream outStream = new ByteArrayOutputStream(32768);
            tf.newTransformer().transform(new DOMSource(doc), new StreamResult(outStream));
            storageService.storeFile(token.getBucket(), token.getOutFilePath(), outStream.toByteArray());

            logger.info("Done creating xml file : " + token.getOutFilePath());

        } catch (JAXBException | TransformerException | ParserConfigurationException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
    }

    //*****************************************************************************************

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

    //*****************************************************************************************

    @Operation(hidden = true)
    @GetMapping(value = GET_METADATA_FOR_TOKEN_URL)
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String tokenString) {
        authorizeCall(features, Features.token);
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
                inputMetadata.setDrawSignature(input.getPsfN() == null && input.getPsfC() == null && !input.isInvisible());
                inputMetadata.setPsfP(input.isPsfP());
                signedInputsMetadata.add(inputMetadata);
            }

            logger.info("Returning from getMetadataForToken()");
            return new DocumentMetadataDTO(token.getSigningType() != SigningType.Standard, !token.isOutDownload(),
                    token.isSelectDocuments(), token.isRequestDocumentReadConfirm(), token.isPreviewDocuments(), token.isNoSkipErrors(), signedInputsMetadata);
        } catch (RuntimeException e){
                logAndThrowEx(tokenString, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    private static String getNameFromPath(String filePath) {
        int pos = filePath.lastIndexOf("/");
        return pos == -1 ? filePath : filePath.substring(pos + 1);
    }

    //*****************************************************************************************

    @Operation(hidden = true)
    @GetMapping(value = GET_FILE_FOR_TOKEN_URL + "/{token}/{type}/{inputIndexes}")
    public void getFileForToken(@PathVariable("token") String tokenString,
                                @PathVariable GetFileType type,
                                @PathVariable(required = true) Integer inputIndexes[],
                                @RequestParam(required = false)  String forceDownload,
                                HttpServletResponse response) {

        authorizeCall(features, Features.token);
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
                        if (!Standard.equals(token.getSigningType()) || inputIndexes.length == 1) singleFilePath = getOutFilePath(token, input);
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
            // Below is a Snyk false positive report : The value is sanitized
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

    //*****************************************************************************************

    @Operation(hidden = true)
    @PostMapping(value = GET_DATA_TO_SIGN_FOR_TOKEN_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        authorizeCall(features, Features.token);
        try {
            checkAndRecordMDCToken(dataToSignForTokenDto.getToken());
            logger.info("Entering getDataToSignForToken()");

            TokenObject token = getTokenFromId(signDto.getToken());
            SigningType sigType = token.getSigningType();

            Date now = signingTime == null ? new Date() : new Date(signingTime);

            // If a whitelist of allowed national numbers is defined in the token, check if the presented certificate national number is allowed to sign the document
            checkNNAllowedToSign(token.getNnAllowedToSign(), signDto.getCertSign());

            RemoteDocument fileToSign = null;
            List<DSSReference> references = null;
            RemoteSignatureParameters parameters = null;
            boolean canSignWithExpiredCertificate = true;
            ProfileSignatureParameters signProfile = null;
            DataToSignForTokenDTO dataToSign = new DataToSignForTokenDTO(now);
            ClientSignatureParameters clientSigParams = new ClientSignatureParameters(signDto.getCertSign(), signDto.getCertChain(), now);
            if (XadesMultiFile.equals(sigType) || MultiFileDetached.equals(sigType)) {
                signProfile = signingConfigService.findProfileParamsById(token.getXmlSignProfile());
                canSignWithExpiredCertificate = signProfile.getSignWithExpiredCertificate();
                parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
                ToBeSignedDTO rawDataToSign = null;
                if (XadesMultiFile.equals(sigType)) {
                    references = buildReferences(now, token, parameters.getReferenceDigestAlgorithm());
                    byte [] bytesToSign = storageService.getFileAsBytes(token.getBucket(), token.getOutFilePath(), true);
                    logger.info("Filesize : " + bytesToSign.length);
                    fileToSign = new RemoteDocument(bytesToSign, null);
                    rawDataToSign = altSignatureService.altGetDataToSign(fileToSign, parameters, references, applicationName);
                } else {
                    rawDataToSign = signatureServiceMultiple.getDataToSign(getDocumentsToSign(token), parameters);
                }
                addDataToSign(dataToSign, parameters, signProfile, rawDataToSign, 0);
            } else {
                long totalSize = 0;
                List<InputToSign> inputsToSign = signDto.getInputsToSign();
                int index = inputsToSign.size();
                while(index != 0) {
                    InputToSign inputToSign = inputsToSign.get(--index);
                    TokenSignInput tokenInputToSign = token.getInputs().get(inputToSign.getIndex());
                    String filePath = tokenInputToSign.getFilePath();
                    boolean isPDF = APPLICATION_PDF.equals(MediaTypeUtil.getMediaTypeFromFilename(filePath));
                    String signProfileId = isPDF ? token.getPdfSignProfile() : token.getXmlSignProfile();
                    signProfile = signingConfigService.findProfileParamsById(signProfileId);
                    canSignWithExpiredCertificate = canSignWithExpiredCertificate & signProfile.getSignWithExpiredCertificate();
                    byte [] photo = tokenInputToSign.isPsfP() || inputToSign.isPsfP() ? signDto.getPhoto() : null;
                    clientSigParams.setPdfSigParams(new VisiblePdfSignatureParameters(inputToSign.getPsfC(), inputToSign.getPsfN(), inputToSign.getLanguage(), photo));
                    parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
                    if (isPDF) {
                        // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                        // or in "ImageIO.read" where it is NOT used as a path !
                        prepareVisibleSignatureForToken(parameters, tokenInputToSign, token.getBucket(), clientSigParams.getPdfSigParams());
                    }
                    byte [] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
                    totalSize += bytesToSign.length;
                    ToBeSignedDTO rawDataToSign = altSignatureService.altGetDataToSign(new RemoteDocument(bytesToSign, null), parameters, null, applicationName);
                    addDataToSign(dataToSign, parameters, signProfile, rawDataToSign, inputToSign.getIndex());
                }
                logger.info("Filesize Total : " + totalSize);
            }
            checkCertificates(canSignWithExpiredCertificate, signDto.getCertSign(), signDto.getCertChain());
            logger.info("Returning from getDataToSignForToken().");
            return dataToSign;
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (AlertException e) {
            String message = e.getMessage();
            if (message == null || !message.startsWith("The new signature field position is outside the page dimensions!")) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
            }
            logger.warning(message);
            logAndThrowEx(INTERNAL_SERVER_ERROR, SIGNATURE_OUT_OF_BOUNDS, e);
        } catch (Exception e) {
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null;
    }

    //*****************************************************************************************

    private void addDataToSign(DataToSignForTokenDTO dataToSign, RemoteSignatureParameters parameters, ProfileSignatureParameters signProfile, ToBeSignedDTO rawDataToSign, int index) {
        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        byte [] bytesToSign = rawDataToSign.getBytes();
        if (signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
        dataToSign.addDigest(digestAlgorithm, bytesToSign, index);
    }

    //*****************************************************************************************

    private List<RemoteDocument> getDocumentsToSign(TokenObject token) {
        long totalSize = 0;
        List<RemoteDocument> toSignDocuments = new ArrayList<>(10);
        for(TokenSignInput input : token.getInputs()) {
            String filePath = input.getFilePath();
            String documentURI = input.getDocumentURI();
            if (documentURI == null) documentURI = filePath;
            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
            toSignDocuments.add(new RemoteDocument(bytesToSign, documentURI));
            totalSize += bytesToSign.length;
        }
        logger.info(" Filesize (total) : " + totalSize);
        return toSignDocuments;
    }

    //*****************************************************************************************

    public void prepareVisibleSignatureForToken(RemoteSignatureParameters remoteSigParams, TokenSignInput input, String bucket, VisiblePdfSignatureParameters pdfParams)
            throws NullParameterException, IOException {

        PdfSignatureProfile psp = getPspFile(input, bucket);
        pdfParams.setPsp(psp);
        String psfN = input.getPsfN();
        if (psfN != null) pdfParams.setPsfN(psfN);
        String psfC = input.getPsfC();
        if (psfC != null) pdfParams.setPsfC(psfC);
        String signLanguage = input.getSignLanguage();
        if (signLanguage != null) pdfParams.setSignLanguage(signLanguage);
        pdfVisibleSignatureService.prepareVisibleSignature(remoteSigParams, input.getPsfNHeight(), input.getPsfNWidth(), pdfParams);
    }

    //*****************************************************************************************

    public PdfSignatureProfile getPspFile(TokenSignInput input, String bucket) {
        PdfSignatureProfile psp = null;
        String pspPath = input.getPspFilePath();
        if (pspPath != null) {
            try {
                byte[] json = storageService.getFileAsBytes(bucket, pspPath, false);
                psp = (new ObjectMapper()).readValue(new String(json), PdfSignatureProfile.class);
            } catch (Exception e) {
                logAndThrowEx(FORBIDDEN, INVALID_PARAM, "Error reading or parsing PDF Signature Profile file: ", e);
            }
        }
        return psp;
    }

    //*****************************************************************************************
    @Operation(hidden = true)
    @PostMapping(value = SIGN_DOCUMENTS_FOR_TOKEN_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<RemoteDocument> signDocumentsForToken(@RequestBody SignDocumentsForTokenDTO signDto) {
        authorizeCall(features, Features.token);
        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentsForToken()");

            TokenObject token = getTokenFromId(signDto.getToken());

            // Signing within allowed time ?
            Date now = signingTime == null ? new Date() : new Date(signingTime);

            long expiredBy = now.getTime() - token.getSignTimeout() * 1000L - signDto.getSigningDate().getTime();
            if (expiredBy > 0) {
                logAndThrowEx(BAD_REQUEST, SIGN_PERIOD_EXPIRED, "Expired by :" + Long.toString(expiredBy / 1000) + " seconds");
            }

            SigningType sigType = token.getSigningType();
            ClientSignatureParameters clientSigParams = new ClientSignatureParameters(signDto.getCertSign(), signDto.getCertChain(), signDto.getSigningDate());

            RemoteDocument signedFile;
            ProfileSignatureParameters signProfile;
            StringBuilder filesNames = new StringBuilder(300);
            List<InputToSign> inputsToSign = signDto.getInputsToSign();
            if (MultiFileDetached.equals(sigType) || XadesMultiFile.equals(sigType)) {
                List<RemoteDocument> documentsToSign = null;
                signProfile = signingConfigService.findProfileParamsById(token.getXmlSignProfile());
                RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
                SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, inputsToSign.get(0).getSignedData());
                eu.europa.esig.dss.enumerations.SignatureLevel oldSignatureLevel = parameters.getSignatureLevel();
                if (XAdES_BASELINE_LTA.equals(oldSignatureLevel)) parameters.setSignatureLevel(XAdES_BASELINE_LT);
                setOverrideRevocationStrategy(signProfile);
                if (MultiFileDetached.equals(sigType)) {
                    signedFile = signatureServiceMultiple.signDocument(documentsToSign = getDocumentsToSign(token), parameters, signatureValueDto);
                } else {
                    List<DSSReference> references = buildReferences(signDto.getSigningDate(), token, parameters.getReferenceDigestAlgorithm());
                    byte [] bytesToSign = storageService.getFileAsBytes(token.getBucket(), token.getOutFilePath(), true);
                    logger.info("Filesize : " + bytesToSign.length);
                    signedFile = altSignatureService.altSignDocument(new RemoteDocument(bytesToSign, null), parameters, signatureValueDto, references, null);
                }
                addCertPathToKeyinfo(signedFile, signDto.getCertChain());
                if (XAdES_BASELINE_LTA.equals(oldSignatureLevel)) {
                    parameters.setSignatureLevel(XAdES_BASELINE_LTA);
                    parameters.setDetachedContents(documentsToSign);
                    signedFile = signatureServiceMultiple.extendDocument(signedFile, parameters);
                }
                String signedName = getOutFilePath(token, null);
                signedFile.setName(signedName);

                // Save signed file
                storageService.storeFile(token.getBucket(), signedName, signedFile.getBytes());
                validateResult(signedFile, documentsToSign, parameters, token, signedFile.getName(), null, signProfile);
                filesNames.append(signedName);
            } else {
                int index = inputsToSign.size();
                while(index != 0) {
                    InputToSign inputToSign = inputsToSign.get(--index);
                    TokenSignInput tokenInputToSign = token.getInputs().get(inputToSign.getIndex());
                    String filePath = tokenInputToSign.getFilePath();
                    boolean isPDF = APPLICATION_PDF.equals(MediaTypeUtil.getMediaTypeFromFilename(filePath));
                    String signProfileId = isPDF ? token.getPdfSignProfile() : token.getXmlSignProfile();
                    signProfile = signingConfigService.findProfileParamsById(signProfileId);
                    byte [] photo = tokenInputToSign.isPsfP() || inputToSign.isPsfP() ? signDto.getPhoto() : null;
                    clientSigParams.setPdfSigParams(new VisiblePdfSignatureParameters(inputToSign.getPsfC(), inputToSign.getPsfN(), inputToSign.getLanguage(), photo));
                    RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, token.getPolicy());
                    if (isPDF) {
                        // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                        // or in "ImageIO.read" where it is NOT used as a path !
                        prepareVisibleSignatureForToken(parameters, tokenInputToSign, token.getBucket(), clientSigParams.getPdfSigParams());
                    }
                    byte [] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
                    RemoteDocument fileToSign = new RemoteDocument(bytesToSign, null);
                    SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, inputToSign.getSignedData());
                    setOverrideRevocationStrategy(signProfile);
                    signedFile = altSignatureService.altSignDocument(fileToSign, parameters, signatureValueDto, null, applicationName);
                    String signedName = getOutFilePath(token, tokenInputToSign);
                    signedFile.setName(signedName);

                    // Save signed file
                    storageService.storeFile(token.getBucket(), signedName, signedFile.getBytes());

                    // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
                    // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
                    List<RemoteDocument> detachedDocuments = clientSigParams.getDetachedContents();
                    if (detachedDocuments == null) detachedDocuments = new ArrayList<>();
                    detachedDocuments.add(fileToSign);
                    validateResult(signedFile, detachedDocuments, parameters, token, signedFile.getName(), null, signProfile);
                    filesNames.append(signedName);
                    if (index != 0) filesNames.append(", ");
                }
            }
            MDC.put("Signed files", filesNames.toString());
            logger.info("Returning from signDocumentsForToken().");
        } catch (Exception e) {
            handleRevokedCertificates(e);
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);
    }

    //*****************************************************************************************

    // For the Justice dept the signature must contain the Full cert path in the KeyInfo element even for all XADES signatures
    // For LT/LTA signatures, EIDAS states that the certs must be present in "CertificateValues/EncapsulatedX509Certificate" but can
    // also be present in the KeyInfo element. DSS does not put the Root cert in the KeyInfo for LT/LTA

    private void addCertPathToKeyinfo(RemoteDocument signedDoc, List<RemoteCertificate> certChain) throws ParserConfigurationException, TransformerException, IOException, SAXException {

        DocumentBuilderFactory dbf = DocumentBuilderFactoryBuilder.getSecureDocumentBuilderFactoryBuilder().build(); // XXE blocked by DSS factory
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(signedDoc.getBytes()));

        //logger.info(xmlDocToString(doc));

        NodeList elements = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Data");
        if (elements == null || elements.getLength() != 1) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INVALID_DOC, "Can't find X509Data to add Root CERT");
        }

        Node x509Data = elements.item(0);
        if (x509Data.getParentNode() == null || "KeyInfo".compareTo(x509Data.getParentNode().getLocalName()) != 0) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INVALID_DOC, "X509Data not enclosed KeyInfo");
        }

        List<String> certsToAdd = new ArrayList<>();
        for(RemoteCertificate cert : certChain) {
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

        logger.log(Level.WARNING, "Adding certificate to KeyInfo");
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

    //*****************************************************************************************

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
    //*****************************************************************************************

    private static String getOutFilePath(TokenObject token, TokenSignInput inputToSign) {
        String prefix = token.getOutPathPrefix();
        return (prefix == null) ? token.getOutFilePath() : prefix + inputToSign.getFilePath();
    }

    //*****************************************************************************************

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters, TokenObject token, String outFilePath, RemoteDocument validatePolicy, ProfileSignatureParameters signProfile) throws IOException {

        String extraTrustFilename = signProfile.getExtraTrustFilename();
        TrustSources trust = extraTrustFilename == null ? null : getGetExtraTrustFile(extraTrustFilename);
        if (validatePolicy == null) {
            if (signProfile.getValidationPolicyFilename() != null) {
                validatePolicy = getPolicyFile(signProfile.getValidationPolicyFilename());
            }
        }

        SignatureFullValiationDTO reportsDto = validationService.validateDocument(signedDoc, detachedContents, validatePolicy, trust, parameters.getSignatureLevel());

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
                // The "best time" of a signature that was just made can be in the past during unit tests... So go back 10s in time.
                reportsService.getLatestSignatureIndicationsDto(reportsDto, new Date(token.getCreateTime() - 10000));

        Indication indication = indications.getIndication();
        if (indication != TOTAL_PASSED) {
            String logReport = System.getProperty("log.validation.report");
            if ("true".equals(logReport)) {
                try {
                    logger.severe(reportsService.createJSONReport(parameters, reportsDto));
                } catch (IOException e) {
                    logger.severe("Can't log report !!!!!!!!");
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

    //*****************************************************************************************

    private void checkCertificates(RemoteSignatureParameters parameters) {
        checkCertificates(parameters.isSignWithExpiredCertificate(), parameters.getSigningCertificate(), parameters.getCertificateChain());
    }

    //*****************************************************************************************

    private void checkCertificates(boolean canSignWithExpiredCertificate, RemoteCertificate signingCert, List<RemoteCertificate> certChain) {
        Date now = new Date();
        // Check if the signing cert is present and not expired
        try {
            if (null == signingCert)
                logAndThrowEx(BAD_REQUEST, NO_SIGN_CERT, "no signing cert present in request");
            byte[] signingCertBytes = signingCert.getEncodedCertificate();
            if (null == signingCertBytes)
                logAndThrowEx(BAD_REQUEST, NO_SIGN_CERT, "could not get encoded signing cert from request");
            X509Certificate signingCrt = (X509Certificate) CertificateFactory.getInstance("X509")
                    .generateCertificate(new ByteArrayInputStream(signingCertBytes));

            logger.info("Signing certificate ID : " + new CertificateToken(signingCrt).getDSSIdAsString());

            // Don't do the expiry check if the profile says to ignore it (only used for testing)
            if (!canSignWithExpiredCertificate && now.after(signingCrt.getNotAfter()))
                logAndThrowEx(BAD_REQUEST, SIGN_CERT_EXPIRED, "exp. date = " + logDateTimeFormat.format(signingCrt.getNotAfter()));
        }
        catch (CertificateException e) {
            logAndThrowEx(BAD_REQUEST, "error parsing signing cert", e.getMessage());
        }

        // Check if the cert chain is present (at least 2 certs)
        if (null == certChain || certChain.size() < 2)
            logAndThrowEx(BAD_REQUEST, CERT_CHAIN_INCOMPLETE, "cert count: " + certChain.size());
    }

    //*****************************************************************************************
    // Save token object to storageService and return a tokenId

    String saveToken(TokenObject token)  {
        String tokenId = null;
        try {
            long now = new Date().getTime();
            token.setCreateTime(now);

            // Build tokenId with random and current time (for collisions)
            byte[] tokenBytes = new byte[SIZE_TOKEN_ID];
            secureRandom.nextBytes(tokenBytes);
            longToBytes(now, tokenBytes, 0, 4);
            tokenId = Base64.getUrlEncoder().encodeToString(tokenBytes);

            // Store token in secret bucket
            ObjectMapper om = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);
            storageService.storeFile(null, KEYS_FOLDER + tokenId + JSON_FILENAME_EXTENSION, om.writeValueAsBytes(token));

            // Cache token
            tokenCache.put(tokenId, token);
        } catch (Exception e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return tokenId;
    }

    //*****************************************************************************************

    // Get token from cache or storageService
    private TokenObject getTokenFromId(String tokenId) {
        TokenObject token = null;
        try {

            token = tokenCache.getIfPresent(tokenId);
            if (token == null) {
                byte[] rawToken = storageService.getFileAsBytes(null, KEYS_FOLDER + tokenId + JSON_FILENAME_EXTENSION, false);
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

    //*****************************************************************************************

    private void checkNNAllowedToSign(List<String> nnAllowedToSign, RemoteCertificate signingCertificate) {
        if (nnAllowedToSign != null) {
            CertInfo certInfo = new CertInfo(signingCertificate);
            String nn = certInfo.getField(CertInfo.Field.serialNumber);
            if (!nnAllowedToSign.contains(nn)) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, NOT_ALLOWED_TO_SIGN, "NN not allowed to sign");
            }
        }
    }

    //*****************************************************************************************

    private List<DSSReference> buildReferences(Date signingTime, TokenObject token, DigestAlgorithm refDigestAlgo) {
        List<String> idsToSign = new ArrayList<>(10);
        for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
        return buildReferences(signingTime, idsToSign, refDigestAlgo);
    }

    //*****************************************************************************************

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

    @PostMapping(value = GET_DATA_TO_SIGN_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(dataToSignDto.getToken());
            RemoteDocument toSignDocument = dataToSignDto.getToSignDocument();
            logger.info("Entering getDataToSign(FileSize : " + toSignDocument.getBytes().length + ")");

            ClientSignatureParameters clientSigParams = dataToSignDto.getClientSignatureParameters();
            clientSigParams.setSigningDate(new Date());
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(dataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);

            setOverrideRevocationStrategy(signProfile);

            checkCertificates(parameters);

            if (SignatureForm.PAdES.equals(signProfile.getSignatureForm())) {
                // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                // or in "ImageIO.read" where it is NOT used as a path !
                prepareVisibleSignature(parameters, toSignDocument, clientSigParams.getPdfSigParams());
            }

            ToBeSignedDTO dataToSign = altSignatureService.altGetDataToSign(toSignDocument, parameters, null, applicationName);

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            byte [] bytesToSign = dataToSign.getBytes();
            if (signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, bytesToSign, dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSign()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (AlertException e) {
            String message = e.getMessage();
            if (message == null || !message.startsWith("The new signature field position is outside the page dimensions!")) {
                logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
            }
            logger.warning(message);
            logAndThrowEx(INTERNAL_SERVER_ERROR, SIGNATURE_OUT_OF_BOUNDS, e);
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    private void prepareVisibleSignature(RemoteSignatureParameters parameters, RemoteDocument pdf, VisiblePdfSignatureParameters pdfParams) throws NullParameterException, IOException {
        if (pdfParams != null) {
            PDRectangle rect = null;
            String psfN = pdfParams.getPsfN();
            String psfC = pdfParams.getPsfC();
            if (psfN != null || psfC != null) {
                PDDocument pdfDoc = PDDocument.load(new ByteArrayInputStream(pdf.getBytes()), (String) null);
                rect = checkVisibleSignatureParameters(psfC, psfN, pdfParams.getPsp(), pdfDoc);
                pdfDoc.close();
            }
            pdfVisibleSignatureService.prepareVisibleSignature(parameters, rect == null ? 0 : rect.getHeight(), rect == null ? 0 : rect.getWidth(), pdfParams);
        }
    }

    //*****************************************************************************************

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
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(dataToSignDto.getToken());
            logger.info("Entering getDataToSignMultiple()");

            dataToSignDto.getClientSignatureParameters().setSigningDate(new Date());
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(dataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, dataToSignDto.getClientSignatureParameters(), null);

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            byte [] bytesToSign = dataToSign.getBytes();
            if (signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, bytesToSign, dataToSignDto.getClientSignatureParameters().getSigningDate());
            logger.info("Returning from getDataToSignMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

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
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(signDocumentDto.getToken());
            RemoteDocument toSignDocument = signDocumentDto.getToSignDocument();
            logger.info("Entering signDocument(FileSize : " + toSignDocument.getBytes().length + ")");

            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDocumentDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);
            setOverrideRevocationStrategy(signProfile);

            if (SignatureForm.PAdES.equals(signProfile.getSignatureForm())) {
                // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                // or in "ImageIO.read" where it is NOT used as a path !
                prepareVisibleSignature(parameters, toSignDocument, clientSigParams.getPdfSigParams());
            }

            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(toSignDocument, parameters, signatureValueDto, null, applicationName);

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            List<RemoteDocument> detachedDocuments = clientSigParams.getDetachedContents();
            if (detachedDocuments == null) detachedDocuments = new ArrayList<>();
            detachedDocuments.add(signDocumentDto.getToSignDocument());

//            try (FileOutputStream fos = new FileOutputStream("signed.file")) { fos.write(signedDoc.getBytes()); }

            RemoteDocument ret =  validateResult(signedDoc, detachedDocuments, parameters, null, null, signDocumentDto.getValidatePolicy(), signProfile);
            logger.info("Returning from signDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

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
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(signDocumentDto.getToken());
            logger.info("Entering signDocumentMultiple()");

            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDocumentDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);
            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDocumentDto.getToSignDocuments(), parameters, signatureValueDto);

            //try (FileOutputStream fos = new FileOutputStream("signed.file.xml")) { fos.write(signedDoc.getBytes()); }

            // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
            // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
            RemoteDocument ret = validateResult(signedDoc, signDocumentDto.getToSignDocuments(), parameters, null, null, signDocumentDto.getValidatePolicy(), signProfile);
            logger.info("Returning from signDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Operation(summary = "Extend the signature of a list of files", description = "Based on an existing signature, raise its signature level by adding the 'long term' attributes (OCSP/CRL evidences) or timestamps")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_MULTIPLE_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocumentMultiple(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(extendDocumentDto.getToken());
            logger.info("Entering extendDocumentMultiple()");

            ProfileSignatureParameters extendProfile = signingConfigService.findProfileParamsById(extendDocumentDto.getExtendProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendProfile, extendDocumentDto.getDetachedContents());
            setOverrideRevocationStrategy(extendProfile);

            RemoteDocument extendedDoc = signatureServiceMultiple.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null, null, null, extendProfile);
            logger.info("Returning from extendDocumentMultiple()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Operation(summary = "Extend the signature of a file", description = "Based on a pre-signed file, raise its signature level by adding the 'long term' attributes (OCSP/CRL evidences) or timestamps")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = EXTEND_DOCUMENT_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(extendDocumentDto.getToken());
            logger.info("Entering extendDocument()");

            ProfileSignatureParameters extendProfile = signingConfigService.findProfileParamsById(extendDocumentDto.getExtendProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendProfile, extendDocumentDto.getDetachedContents());
            setOverrideRevocationStrategy(extendProfile);

            RemoteDocument extendedDoc = altSignatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            RemoteDocument ret = validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters, null, null, null, extendProfile);
            logger.info("Returning from extendDocument()");
            return ret;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    @Operation(summary = "Timestamp a file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "No error",
                    content = { @Content(mediaType = "application/json", schema = @Schema(implementation = RemoteDocument.class)) }),
            @ApiResponse(responseCode = "400", description = "Invalid profile",
                    content = { @Content(mediaType = "text/plain") }),
            @ApiResponse(responseCode = "500", description = "Technical error",
                    content = { @Content(mediaType = "text/plain") })
    })

    @PostMapping(value = TIMESTAMP_DOCUMENT_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        authorizeCall(features, Features.signbox);
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

    //*****************************************************************************************

    @Operation(summary = "Timestamp a list of files and produce a file in ASIC format")
    @PostMapping(value = TIMESTAMP_DOCUMENT_MULTIPLE_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocumentMultiple(@RequestBody TimestampDocumentMultipleDTO timestampDocumentDto) {
        authorizeCall(features, Features.signbox);
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

    //*****************************************************************************************

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

    @PostMapping(value = GET_DATA_TO_SIGN_XADES_MDOC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignXMLElementsDTO getDataToSignDto) {
        authorizeCall(features, Features.signbox);
        try {
            checkAndRecordMDCToken(getDataToSignDto.getToken());
            logger.info("Entering getDataToSignXades()");

            ClientSignatureParameters clientSigParams = getDataToSignDto.getClientSignatureParameters();
            Date signingDate = new Date();
            clientSigParams.setSigningDate(signingDate);

            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(getDataToSignDto.getSigningProfileId());
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);

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
        } catch(ProtectedDocumentException e) {
            logAndThrowEx(UNAUTHORIZED, NOT_ALLOWED_TO_SIGN, e.getMessage());
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

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

    @PostMapping(value = SIGN_DOCUMENT_XADES_MDOC_URL, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignXMLElementsDTO signDto) {
        authorizeCall(features, Features.signbox);

        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentXades()");

            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(signDto.getSigningProfileId());
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams, null);
            setOverrideRevocationStrategy(signProfile);

            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDto.getSignatureValue());
            List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), signDto.getElementIdsToSign(), parameters.getReferenceDigestAlgorithm());
            RemoteDocument signedDoc = altSignatureService.altSignDocument(signDto.getToSignDocument(), parameters, signatureValueDto, references, null);

            signedDoc.setName(signDto.getToSignDocument().getName());
            logger.info("Returning from signDocumentXades()");
            return signedDoc;
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureService.PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException | IOException e) {
            handleRevokedCertificates(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public static SignatureValueDTO getSignatureValueDTO(RemoteSignatureParameters parameters, byte[] signatureValue) {
        return new SignatureValueDTO(SignatureAlgorithm.getAlgorithm(parameters.getEncryptionAlgorithm(), parameters.getDigestAlgorithm()), signatureValue);
    }

    //*****************************************************************************************

private static void handleRevokedCertificates(Exception e) {
    if (e instanceof AlertException && e.getMessage().startsWith("Revoked/Suspended certificate")) {
        logAndThrowEx(BAD_REQUEST, DOC_CERT_REVOKED, e);
    }
}

//*****************************************************************************************

public enum Features {
    validation,token,signbox
}

//*****************************************************************************************

public static void authorizeCall(String features, Features feature) {
    if (features != null && !features.contains(feature.name())) throw new InvalidParameterException("Unknown Operation");
}

//*****************************************************************************************
}
