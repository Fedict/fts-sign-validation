package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.config.ThreadDataCleaner;
import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.utils.MediaTypeUtil;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.model.VisiblePdfSignatureParameters;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signingconfigurator.exception.NullParameterException;
import com.bosa.signingconfigurator.exception.ProfileNotFoundException;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xml.common.DocumentBuilderFactoryBuilder;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

import static com.bosa.signandvalidation.config.ErrorStrings.*;
import static com.bosa.signandvalidation.exceptions.Utils.*;
import static com.bosa.signandvalidation.model.SigningType.*;
import static com.bosa.signandvalidation.utils.SupportUtils.longToBytes;

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

import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.*;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

@Service
public class TokenSignService extends SignCommonService {
    protected final Logger logger = Logger.getLogger(TokenSignService.class.getName());

    private static final int SIZE_TOKEN_ID                      = 12;
    public static final int DEFAULT_SIGN_DURATION_SECS          = 2 * 60;
    public static final int MAX_NN_ALLOWED_TO_SIGN              = 32;
    private static final Pattern nnPattern                      = Pattern.compile("[0-9]{11}");
    private static final Pattern eltIdPattern                   = Pattern.compile("[a-zA-Z0-9\\-_]{1,30}");

    public static final String KEYS_FOLDER                      = "keys/";
    private static final String JSON_FILENAME_EXTENSION         = ".json";

    // Secret key cache
    private static final Cache<String, TokenObject> tokenCache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).build();

    // Token timeout is 5 hours (300 minutes) or else
    @Value("${token.timeout:300}")
    private Integer defaultTokenTimeout;

    @Value("${signing.time}")
    private Long signingTime;

    private final SecureRandom secureRandom = new SecureRandom();

    //*****************************************************************************************

    public String getTokenForDocument(GetTokenForDocumentDTO tokenData) {
        try {
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

    public String getTokenForDocuments(GetTokenForDocumentsDTO gtfd) throws IllegalAccessException {
        try {
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
            PDDocument pdfDoc = Loader.loadPDF(file);
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

    public void validateTokenValues(TokenObject token) {

        SigningType signingType = token.getSigningType();
        String pdfProfileId = token.getPdfSignProfile();
        String xmlProfileId = token.getXmlSignProfile();

        Integer tokenTimeout = token.getTokenTimeout();
        if (defaultTokenTimeout == null) defaultTokenTimeout = 300;
        if (tokenTimeout == null) token.setTokenTimeout(tokenTimeout = defaultTokenTimeout * 60);

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

    public DocumentMetadataDTO getMetadataForToken(String tokenString) {
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

    public void getFileForToken(String tokenString,
                                GetFileType type,
                                Integer inputIndexes[],
                                String forceDownload,
                                HttpServletResponse response) {

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

    public DataToSignDTO getDataToSignForToken(GetDataToSignForTokenDTO dataToSignForTokenDto) {
        try {
            checkAndRecordMDCToken(dataToSignForTokenDto.getToken());
            logger.info("Entering getDataToSignForToken()");

            TokenObject token = getTokenFromId(dataToSignForTokenDto.getToken());
            ClientSignatureParameters clientSigParams = dataToSignForTokenDto.getClientSignatureParameters();

            // Signer allowed to sign ?
            checkNNAllowedToSign(token.getNnAllowedToSign(), clientSigParams.getSigningCertificate());

            Date signingDate = signingTime == null ? new Date() : new Date(signingTime);
            clientSigParams.setSigningDate(signingDate);

            String filePath = null;
            MediaType mediaType = null;
            TokenSignInput inputToSign = null;
            String profileId = token.getXmlSignProfile();
            if (Standard.equals(token.getSigningType())) {
                inputToSign = token.getInputs().get(dataToSignForTokenDto.getFileIdToSign());
                filePath = inputToSign.getFilePath();
                mediaType = MediaTypeUtil.getMediaTypeFromFilename(filePath);
                if (APPLICATION_PDF.equals(mediaType)) profileId = token.getPdfSignProfile();
            }
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(profileId);
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);
            checkCertificates(parameters);

            ToBeSignedDTO dataToSign;
            switch (token.getSigningType()) {
                case MultiFileDetached:
                    dataToSign = signatureServiceMultiple.getDataToSign(getDocumentsToSign(token), parameters);
                    break;

                case XadesMultiFile:
                    List<DSSReference> references = buildReferences(signingDate, token, parameters.getReferenceDigestAlgorithm());
                    RemoteDocument fileToSign = getDocumentToSign(token, token.getOutFilePath());
                    dataToSign = altSignatureService.altGetDataToSign(fileToSign, parameters, references, applicationName);
                    break;

                default:
                    if (APPLICATION_PDF.equals(mediaType)) {
                        // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                        // or in "ImageIO.read" where it is NOT used as a path !
                        prepareVisibleSignatureForToken(parameters, inputToSign, token.getBucket(), clientSigParams);
                    }

                    fileToSign = getDocumentToSign(token, filePath);
                    dataToSign = altSignatureService.altGetDataToSign(fileToSign, parameters, null, applicationName);
                    break;
            }

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            byte [] bytesToSign = dataToSign.getBytes();
            if (signProfile.isReturnDigest()) bytesToSign = DSSUtils.digest(digestAlgorithm, bytesToSign);
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, bytesToSign, clientSigParams.getSigningDate());

            logger.info("Returning from getDataToSignForToken()");

            return ret;
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
        return null; // We won't get here
    }

    //****************************************************************************************

    private List<RemoteDocument> getDocumentsToSign(TokenObject token) {
        List<RemoteDocument> toSignDocuments = new ArrayList<>(10);
        for(TokenSignInput input : token.getInputs()) {
            String filePath = input.getFilePath();
            String documentURI = input.getDocumentURI();
            if (documentURI == null) documentURI = filePath;
            byte[] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
            logger.info("File : " + filePath + " - Size : " + bytesToSign.length);
            toSignDocuments.add(new RemoteDocument(bytesToSign, documentURI));
        }
        return toSignDocuments;
    }

    //*****************************************************************************************

    private RemoteDocument getDocumentToSign(TokenObject token, String filePath) {
        byte [] bytesToSign = storageService.getFileAsBytes(token.getBucket(), filePath, true);
        logger.info("File : " + filePath + " - Size : " + bytesToSign.length);
        return new RemoteDocument(bytesToSign, filePath);
    }

    //*****************************************************************************************

    public void prepareVisibleSignatureForToken(RemoteSignatureParameters remoteSigParams, TokenSignInput input, String bucket, ClientSignatureParameters clientSigParams)
            throws NullParameterException, IOException {

        VisiblePdfSignatureParameters pdfParams = clientSigParams.getPdfSigParams();
        PdfSignatureProfile psp = getPspFile(input, bucket);
        pdfParams.setPsp(psp);
        String psfN = input.getPsfN();
        if (psfN != null) pdfParams.setPsfN(psfN);
        String psfC = input.getPsfC();
        if (psfC != null) pdfParams.setPsfC(psfC);
        SigningLanguages signLanguage = input.getSignLanguage();
        if (signLanguage != null) pdfParams.setSignLanguage(signLanguage.name());
        pdfVisibleSignatureService.prepareVisibleSignature(remoteSigParams, input.getPsfNHeight(), input.getPsfNWidth(), clientSigParams);
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

    @Async("asyncTasks")
    public CompletableFuture<Object> signDocumentForTokenAsync(SignDocumentForTokenDTO signDto) {
        CompletableFuture<Object> task = new CompletableFuture<>();
        try {
            signDocumentForToken(signDto);
            task.complete(null);
        } catch(Exception e){
            task.completeExceptionally(e);
        } finally {
            // We're on a different thread (ASYNC) so clear all thread data
            ThreadDataCleaner.clearAll();
        }
        return task;
    }

    //*****************************************************************************************

    private void signDocumentForToken(SignDocumentForTokenDTO signDto) {
        try {
            checkAndRecordMDCToken(signDto.getToken());
            logger.info("Entering signDocumentForToken()");

            TokenObject token = getTokenFromId(signDto.getToken());
            SigningType sigType = token.getSigningType();
            ClientSignatureParameters clientSigParams = signDto.getClientSignatureParameters();

            // Signing within allowed time ?
            Date now = signingTime == null ? new Date() : new Date(signingTime);

            long expiredBy = now.getTime() - token.getSignTimeout() * 1000L - clientSigParams.getSigningDate().getTime();
            if (expiredBy > 0) {
                logAndThrowEx(BAD_REQUEST, SIGN_PERIOD_EXPIRED, "Expired by :" + Long.toString(expiredBy / 1000) + " seconds");
            }

            // If a whitelist of allowed national numbers is defined in the token, check if the presented certificate national number is allowed to sign the document
            checkNNAllowedToSign(token.getNnAllowedToSign(), clientSigParams.getSigningCertificate());

            String filePath = null;
            MediaType mediaType = null;
            TokenSignInput inputToSign = null;
            String profileId = token.getXmlSignProfile();
            if (Standard.equals(sigType)) {
                inputToSign = token.getInputs().get(signDto.getFileIdToSign());
                filePath = inputToSign.getFilePath();
                mediaType = MediaTypeUtil.getMediaTypeFromFilename(filePath);
                if (APPLICATION_PDF.equals(mediaType)) profileId = token.getPdfSignProfile();
            }
            ProfileSignatureParameters signProfile = signingConfigService.findProfileParamsById(profileId);
            setOverrideRevocationStrategy(signProfile);
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signProfile, clientSigParams);
            checkCertificates(parameters);
            SignatureValueDTO signatureValueDto = getSignatureValueDTO(parameters, signDto.getSignatureValue());

            RemoteDocument signedDoc;
            RemoteDocument fileToSign;
            List<RemoteDocument> detachedDocuments = null;
            if (MultiFileDetached.equals(sigType) || XadesMultiFile.equals(sigType)) {
                eu.europa.esig.dss.enumerations.SignatureLevel oldSignatureLevel = parameters.getSignatureLevel();
                if (eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LTA.equals(oldSignatureLevel)) {
                    parameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LT);
                }
                if (MultiFileDetached.equals(sigType)) {
                    signedDoc = signatureServiceMultiple.signDocument(detachedDocuments = getDocumentsToSign(token), parameters, signatureValueDto);
                } else {
                    List<DSSReference> references = buildReferences(clientSigParams.getSigningDate(), token, parameters.getReferenceDigestAlgorithm());
                    fileToSign = getDocumentToSign(token, token.getOutFilePath());
                    signedDoc = altSignatureService.altSignDocument(fileToSign, parameters, signatureValueDto, references, null);
                }
                addCertPathToKeyinfo(signedDoc, clientSigParams);
                if (eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LTA.equals(oldSignatureLevel)) {
                    parameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LTA);
                    parameters.setDetachedContents(detachedDocuments);
                    signedDoc = signatureServiceMultiple.extendDocument(signedDoc, parameters);
                }
            } else {
                if (APPLICATION_PDF.equals(mediaType)) {
                    // Below is a Snyk false positive report : The "traversal" is in PdfVisibleSignatureService.getFont
                    // or in "ImageIO.read" where it is NOT used as a path !
                    prepareVisibleSignatureForToken(parameters, inputToSign, token.getBucket(), clientSigParams);
                }

                fileToSign = getDocumentToSign(token, filePath);
                signedDoc = altSignatureService.altSignDocument(fileToSign, parameters, signatureValueDto, null, applicationName);

                // Adding the source document as detacheddocuments is needed when using a "DETACHED" sign profile,
                // as it happens that "ATTACHED" profiles don't bother the detacheddocuments parameters we're adding them at all times
                detachedDocuments = clientSigParams.getDetachedContents();
                if (detachedDocuments == null) detachedDocuments = new ArrayList<>();
                detachedDocuments.add(fileToSign);
            }

            signedDoc.setName(getOutFilePath(token, inputToSign));

            logger.info("signDocumentForToken(): validating the signed doc");

            signedDoc = validateResult(signedDoc, detachedDocuments, parameters, token, signedDoc.getName(), null, signProfile);

            // Save signed file
            storageService.storeFile(token.getBucket(), signedDoc.getName(), signedDoc.getBytes());

            // Log bucket and filename only for this method
            MDC.put("bucket", token.getBucket());
            MDC.put("fileName", signedDoc.getName());
            logger.info("Returning from signDocumentForToken().");
        } catch (Exception e) {
            handleRevokedCertificates(e);
            DataLoadersExceptionLogger.logAndThrow(e);
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
    }

    //*****************************************************************************************

    // For the Justice dept the signature must contain the Full cert path in the KeyInfo element even for all XADES signatures
    // For LT/LTA signatures, EIDAS states that the certs must be present in "CertificateValues/EncapsulatedX509Certificate" but can
    // also be present in the KeyInfo element. DSS does not put the Root cert in the KeyInfo for LT/LTA

    private void addCertPathToKeyinfo(RemoteDocument signedDoc, ClientSignatureParameters clientSigParams) throws ParserConfigurationException, TransformerException, IOException, SAXException {

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

    List<DSSReference> buildReferences(Date signingTime, TokenObject token, DigestAlgorithm refDigestAlgo) {
        List<String> idsToSign = new ArrayList<>(10);
        for(TokenSignInput input : token.getInputs()) idsToSign.add(input.getXmlEltId());
        return buildReferences(signingTime, idsToSign, refDigestAlgo);
    }

    //*****************************************************************************************

    private static String getOutFilePath(TokenObject token, TokenSignInput inputToSign) {
        String prefix = token.getOutPathPrefix();
        return (prefix == null) ? token.getOutFilePath() : prefix + inputToSign.getFilePath();
    }

    //*****************************************************************************************
    // Save token object to storageService and return a tokenId

    public String saveToken(TokenObject token)  {
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
}
