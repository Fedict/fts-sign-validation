package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.model.*;
import com.bosa.signandvalidation.dataloaders.DataLoadersExceptionLogger;
import com.bosa.signandvalidation.utils.OCSPOnlyRevocationDataLoadingStrategy;
import com.bosa.signandvalidation.utils.OCSPOnlyForLeafRevocationDataLoadingStrategy;
import com.bosa.signingconfigurator.model.ProfileSignatureParameters;
import com.bosa.signingconfigurator.service.SigningConfiguratorService;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteMultipleDocumentsSignatureService;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.xml.security.transforms.Transforms;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

import static com.bosa.signandvalidation.config.ErrorStrings.*;
import static com.bosa.signandvalidation.config.ThreadedCertificateVerifier.setOverrideRevocationDataLoadingStrategyFactory;
import static com.bosa.signandvalidation.exceptions.Utils.*;
import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.DEFAULT_STRING;
import static com.bosa.signandvalidation.service.PdfVisibleSignatureService.TRANSPARENT;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.regex.Pattern;

import static org.springframework.http.HttpStatus.*;

public class SignCommonService {
    private static final Pattern pspColorPattern               = Pattern.compile("(#[0-9a-fA-F]{6}|" + TRANSPARENT + ")");
    private static final Pattern pspFontPattern                = Pattern.compile(".*(/b|/i|/bi|/ib)?"); // <FontName>/<b><i>. Sample : "Serif/bi"

    private static final SimpleDateFormat logDateTimeFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");

    @Autowired
    private ReportsService reportsService;

    @Autowired
    private BosaRemoteDocumentValidationService validationService;

    @Autowired
    protected SigningConfiguratorService signingConfigService;

    @Autowired
    protected PdfVisibleSignatureService pdfVisibleSignatureService;

    @Autowired
    protected RemoteMultipleDocumentsSignatureService signatureServiceMultiple;

    @Autowired
    protected RemoteAltSignatureServiceImpl altSignatureService;

    @Autowired
    StorageService storageService;

    @Value("BOSA FTS v${application.version}")
    protected String applicationName;

    //*****************************************************************************************

    private static void checkPspColor(String color, String name) {
        if (color != null && !pspColorPattern.matcher(color).matches()) {
            logAndThrowEx(FORBIDDEN, INVALID_PARAM, "'" + name + "' (" + color + ") does not match Regex (" + pspColorPattern.pattern() + ")" , null);
        }
    }

    //*****************************************************************************************

    public static void checkPsfC(PDDocument pdfDoc, String psfC) {
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

    // This mechanism allow dynamic control over the CertificateVerifier for the RevocationDataLoadingStrategyFactory
    // based on the signProfile "revocationStrategy" attribute
    void setOverrideRevocationStrategy(ProfileSignatureParameters signProfile) {
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

    RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters, TokenObject token, String outFilePath, RemoteDocument validatePolicy, ProfileSignatureParameters signProfile) throws IOException {

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

// In order to keep coherence between token and non-toke operations the validation code is the same
public static PDRectangle checkVisibleSignatureParameters(String psfC, String psfN, PdfSignatureProfile psp, PDDocument pdfDoc) {
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

    void checkCertificates(RemoteSignatureParameters parameters) {

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

            logger.info("Signing certificate ID : " + new CertificateToken(signingCrt).getDSSIdAsString());

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

    //*****************************************************************************************

    List<DSSReference> buildReferences(Date signingTime, List<String> xmlIds, DigestAlgorithm refDigestAlgo) {

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

    //*****************************************************************************************

    public static SignatureValueDTO getSignatureValueDTO(RemoteSignatureParameters parameters, byte[] signatureValue) {
        return new SignatureValueDTO(SignatureAlgorithm.getAlgorithm(parameters.getEncryptionAlgorithm(), parameters.getDigestAlgorithm()), signatureValue);
    }

    //*****************************************************************************************

    static void handleRevokedCertificates(Exception e) {
        if (e instanceof AlertException && e.getMessage().startsWith("Revoked/Suspended certificate")) {
            logAndThrowEx(BAD_REQUEST, DOC_CERT_REVOKED, e);
        }
    }
}
