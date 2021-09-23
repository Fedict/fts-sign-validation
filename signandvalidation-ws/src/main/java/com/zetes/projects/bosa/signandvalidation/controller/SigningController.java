package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;

import com.nimbusds.jose.JOSEException;
import com.zetes.projects.bosa.signandvalidation.TokenParser;
import com.zetes.projects.bosa.signandvalidation.TokenParser.TokenExpiredException;
import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService;
import com.zetes.projects.bosa.signandvalidation.service.PdfVisibleSignatureService;
import com.zetes.projects.bosa.signandvalidation.service.PdfVisibleSignatureService.PdfVisibleSignatureException;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService.InvalidKeyConfigException;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService.TokenCreationFailureException;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.service.SigningConfiguratorService;
import com.zetes.projects.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureService;
import eu.europa.esig.dss.ws.signature.common.RemoteMultipleDocumentsSignatureService;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.List;
import java.util.logging.Level;
import java.text.SimpleDateFormat;

import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import eu.europa.esig.dss.enumerations.Indication;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping(value = "/signing")
public class SigningController extends ControllerBase implements ErrorStrings {

    @Autowired
    private SigningConfiguratorService signingConfigService;

    @Autowired
    private PdfVisibleSignatureService pdfVisibleSignatureService;

    @Autowired
    private RemoteDocumentSignatureService signatureService;

    @Autowired
    private RemoteMultipleDocumentsSignatureService signatureServiceMultiple;

    @Autowired
    private BosaRemoteDocumentValidationService validationService;

    @Autowired
    private ReportsService reportsService;
    
    @Autowired
    private ObjectStorageService ObjStorageService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    private static SimpleDateFormat logDateTimeFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
    private static SimpleDateFormat reportDateTimeFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    @PostMapping(value = "/getDataToSign", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters());

            checkDataToSign(parameters, null);

            ToBeSignedDTO dataToSign = signatureService.getDataToSign(dataToSignDto.getToSignDocument(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()));
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureException e) {
            logAndThrowEx(BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }
    
    @PostMapping(value="/getDataToSignForToken", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        String token = dataToSignForTokenDto.getToken();
        logger.log(Level.INFO, "Entering getDataToSignForToken()" + token2str(token));
        try {
            ClientSignatureParameters clientSigParams = dataToSignForTokenDto.getClientSignatureParameters();
            TokenParser tokenParser = ObjStorageService.parseToken(token, 60 * 5);

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(
                tokenParser.getProf(), clientSigParams);
            RemoteDocument document = ObjStorageService.getDocumentForToken(tokenParser, false);

            checkDataToSign(parameters, token);
            if (parameters.getSignatureLevel().toString().startsWith("PAdES"))
                pdfVisibleSignatureService.checkAndFillParams(parameters, document, tokenParser, clientSigParams.getPhoto());

            ToBeSignedDTO dataToSign = signatureService.getDataToSign(document, parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            DataToSignDTO ret = new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()));

            logger.log(Level.INFO, "Returning from getDataToSignForToken()" + token2str(token));

            return ret;
        } catch (ObjectStorageService.InvalidTokenException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, e);
        } catch(NullParameterException e) {
            logAndThrowEx(token, BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(token, BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (PdfVisibleSignatureException e) {
            logAndThrowEx(token, BAD_REQUEST, ERR_PDF_SIG_FIELD, e.getMessage());
        } catch (InvalidKeyConfigException e) {
            logAndThrowEx(token, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (TokenParser.TokenExpiredException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, "token has expired");
        } catch (RuntimeException e) {
            logAndThrowEx(token, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value="/getTokenForDocument", produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocument(@RequestBody GetTokenForDocumentDTO tokenData) {
        try {
            if(!(ObjStorageService.isValidAuth(tokenData.getName(), tokenData.getPwd()))) {
                logAndThrowEx(FORBIDDEN, INVALID_S3_LOGIN, null, null);
            }
            String token = ObjStorageService.getTokenForDocument(tokenData.getName(), tokenData.getIn(), tokenData.getOut(),
                tokenData.getProf(), tokenData.getXslt(), tokenData.getPsp(), tokenData.getPsfN(), tokenData.getPsfC(), tokenData.getPsfP(), tokenData.getLang(),
                tokenData.getNoDownload());
            logger.log(Level.INFO, "Returning from getTokenForDocument()" + token2str(token) + "\nparams: " + tokenData.toString());
            return token;
        } catch (TokenCreationFailureException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (InvalidKeyConfigException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @GetMapping(value="/getDocumentForToken")
    public void getDocumentForToken(HttpServletResponse response,
                                    HttpServletRequest request) {
        String token = null;
        try {
            String[] qs = request.getQueryString().split("&");
            String type = null;
            for(String item : qs) {
                if(item.startsWith("token")) {
                    token = item.substring(item.indexOf("=") + 1);
                }
                if(item.startsWith("type")) {
                    type = item.substring(item.indexOf("=") + 1);
                }
            }
            if(null == token) {
                logAndThrowEx(BAD_REQUEST, NO_TOKEN, "query=" + request.getQueryString(), null);
            }
            logger.log(Level.INFO, "Entering getDocumentForToken(type=" + type +")" + token2str(token));
            boolean wantXslt = false;
            if(type != null) {
                if ("xslt".equals(type)) {
                    wantXslt = true;
                } else {
                    logAndThrowEx(token, BAD_REQUEST, INVALID_TYPE, null, null);
                }
            }
            TokenParser tp = ObjStorageService.parseToken(token, 5);
            byte[] rv = ObjStorageService.getDocumentForToken(tp, wantXslt).getBytes();
            DocumentMetadataDTO typeForToken = ObjStorageService.getTypeForToken(tp);
            response.setContentType(typeForToken.getMimetype());
            if((typeForToken.getMimetype().equals("application/pdf"))) {
                response.setHeader("Content-Disposition", "inline; filename=" + typeForToken.getFilename());
            } else {
                response.setHeader("Content-Disposition", "attachment; filename=" + typeForToken.getFilename());
            }
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Cache-Control", "no-cache");
            response.getOutputStream().write(rv);
            logger.log(Level.INFO, "Returning from getDocumentForToken(type=" + type +")" + token2str(token));
        } catch (IOException e) {
            logAndThrowEx(token, BAD_REQUEST, INTERNAL_ERR, e);
        } catch (TokenParser.TokenExpiredException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, "token has expired");
        } catch (ObjectStorageService.InvalidTokenException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, e);
        } catch (ObjectStorageService.InvalidKeyConfigException e) {
            logAndThrowEx(token, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (RuntimeException e) {
            logAndThrowEx(token, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
    }

    @GetMapping(value="/getMetadataForToken")
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String token) {
        logger.log(Level.INFO, "Entering getMetadataForToken()" + token2str(token));
        try {
            DocumentMetadataDTO ret = ObjStorageService.getTypeForToken(token);
            logger.log(Level.INFO, "Returning from getMetadataForToken()" + token2str(token));
            return ret;
        } catch (TokenParser.TokenExpiredException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, "token has expired");
        } catch (ObjectStorageService.InvalidTokenException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, e);
        } catch (ObjectStorageService.InvalidKeyConfigException | RuntimeException e) {
            logAndThrowEx(token, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/getDataToSignMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignMultiple(@RequestBody GetDataToSignMultipleDTO dataToSignDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters());

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()));
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureService.signDocument(signDocumentDto.getToSignDocument(), parameters, signatureValueDto);

            return validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }
    
    @PostMapping(value = "/signDocumentForToken", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<RemoteDocument> signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDocumentDto) {
        String token = signDocumentDto.getToken();
        logger.log(Level.INFO, "Entering signDocumentForToken()" + token2str(token));
        try {
            ClientSignatureParameters clientSigParams = signDocumentDto.getClientSignatureParameters();
            TokenParser tp = ObjStorageService.parseToken(token, 60 * 5);
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(ObjStorageService.getProfileForToken(tp), clientSigParams);
            RemoteDocument document = ObjStorageService.getDocumentForToken(tp, false);

            if (parameters.getSignatureLevel().toString().startsWith("PAdES"))
                pdfVisibleSignatureService.checkAndFillParams(parameters, document, tp, clientSigParams.getPhoto());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureService.signDocument(document, parameters, signatureValueDto);
            signedDoc.setName(ObjStorageService.getTypeForToken(tp).getFilename());

            logger.log(Level.INFO, "signDocumentForToken(): validating the signed doc" + token2str(token));
            signedDoc = validateResult(signedDoc, clientSigParams.getDetachedContents(), parameters, tp);
            ObjStorageService.storeDocumentForToken(tp, signedDoc);

            logger.log(Level.INFO, "Returning from signDocumentForToken()" + token2str(token));

            if(tp.getNoDownload()) {
                return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);
            } else {
                return new ResponseEntity<>(signedDoc, HttpStatus.OK);
            }
        } catch(ObjectStorageService.InvalidTokenException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(token, BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(token, BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (TokenParser.TokenExpiredException e) {
            logAndThrowEx(token, BAD_REQUEST, INVALID_TOKEN, "token has expired");
        } catch (InvalidKeyConfigException | RuntimeException e) {
            logAndThrowEx(token, INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/signDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentMultiple(@RequestBody SignDocumentMultipleDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDocumentDto.getToSignDocuments(), parameters, signatureValueDto);

            return validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch(NullParameterException e) {
            logAndThrowEx(BAD_REQUEST, EMPTY_PARAM, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/extendDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = signatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            return validateResult(extendedDoc, extendDocumentDto.getDetachedContents(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/extendDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
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

    @PostMapping(value = "/timestampDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        try {
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            return signatureService.timestamp(timestampDocumentDto.getDocument(), parameters);
        } catch (ProfileNotFoundException e) {
            logAndThrowEx(BAD_REQUEST, UNKNOWN_PROFILE, e.getMessage());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/timestampDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
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

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters) {
        return validateResult(signedDoc, detachedContents, parameters, null);
    }

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents, RemoteSignatureParameters parameters, TokenParser tokenParser) {
        WSReportsDTO reportsDto = validationService.validateDocument(signedDoc, detachedContents, null);

        if (null != tokenParser) {
            try {
                // Instead of saving the entire report, create our own report containing the simple/detailed reports and the signing cert
                byte[] sigingCert = parameters.getSigningCertificate().getEncodedCertificate();
                ReportDTO reportDto = new ReportDTO(reportsDto.getSimpleReport(), reportsDto.getDetailedReport(), sigingCert);

                StringWriter out = new StringWriter();
                ObjectMapper mapper = new ObjectMapper();
                mapper.setDateFormat(reportDateTimeFormat);
                mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
                mapper.writeValue(out, reportDto);

                RemoteDocument reportsDoc = new RemoteDocument();
                reportsDoc.setBytes(out.toString().getBytes());
                ObjStorageService.storeDocumentForToken(tokenParser, reportsDoc, ".validationreport.json");
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

    private void checkDataToSign(RemoteSignatureParameters parameters, String token) {
        
        // Check signing date
        Date now = new Date();
        Calendar oldest = Calendar.getInstance();
        oldest.setTime(now);
        oldest.add(Calendar.MINUTE, -5);
        Calendar newest = Calendar.getInstance();
        newest.setTime(now);
        newest.add(Calendar.MINUTE, 5);
        Date d = parameters.getBLevelParams().getSigningDate();
        if((d.compareTo(newest.getTime()) > 0) || (d.compareTo(oldest.getTime()) < 0)) {
            logAndThrowEx(BAD_REQUEST, INVALID_SIG_DATE, logDateTimeFormat.format(d));
        }

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

            // Log the cert ID, so it can be linked to the token
            if (null != token)
                logger.log(Level.INFO, "Signing certificate ID for " + token2str(token) + " : " + new CertificateToken(signingCrt).getDSSIdAsString());            

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
}
