package com.zetes.projects.bosa.signandvalidation.controller;

import com.nimbusds.jose.JOSEException;
import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService.InvalidKeyConfigException;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService.TokenCreationFailureException;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import com.zetes.projects.bosa.signingconfigurator.exception.NullParameterException;
import com.zetes.projects.bosa.signingconfigurator.exception.ProfileNotFoundException;
import com.zetes.projects.bosa.signingconfigurator.service.SigningConfiguratorService;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
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
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/signing")
public class SigningController implements ErrorStrings {

    @Autowired
    private SigningConfiguratorService signingConfigService;

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

    @PostMapping(value = "/getDataToSign", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSign(@RequestBody GetDataToSignDTO dataToSignDto) {
        try {
            checkDataToSign(dataToSignDto.getClientSignatureParameters());

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters());

            ToBeSignedDTO dataToSign = signatureService.getDataToSign(dataToSignDto.getToSignDocument(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()));
        } catch (ProfileNotFoundException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }
    
    @PostMapping(value="/getDataToSignForToken", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignForToken(@RequestBody GetDataToSignForTokenDTO dataToSignForTokenDto) {
        try {
            checkDataToSign(dataToSignForTokenDto.getClientSignatureParameters());

            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(ObjStorageService.getProfileForToken(dataToSignForTokenDto.getToken()), dataToSignForTokenDto.getClientSignatureParameters());

            ToBeSignedDTO dataToSign = signatureService.getDataToSign(ObjStorageService.getDocumentForToken(dataToSignForTokenDto.getToken()), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()));
        } catch (ProfileNotFoundException | NullParameterException
                | ObjectStorageService.InvalidTokenException | JOSEException
                | ParseException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        } catch (InvalidKeyConfigException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR);
        }
    }
    @PostMapping(value="/getTokenForDocument", produces = TEXT_PLAIN_VALUE, consumes = APPLICATION_JSON_VALUE)
    public String getTokenForDocument(@RequestBody GetTokenForDocumentDTO tokenData) {
        try {
            if(!(ObjStorageService.isValidAuth(tokenData.getName(), tokenData.getPwd()))) {
                throw new ResponseStatusException(FORBIDDEN, INVALID_S3_LOGIN);
            }
            return ObjStorageService.getTokenForDocument(tokenData.getName(), tokenData.getIn(), tokenData.getOut(), tokenData.getProf());
        } catch (TokenCreationFailureException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        } catch (InvalidKeyConfigException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR);
        }
    }
    @GetMapping(value="/getDocumentForToken")
    public void getDocumentForToken(HttpServletResponse response,
                                    HttpServletRequest request) {
        try {
            String[] qs = request.getQueryString().split("&");
            String token = null;
            for(String item : qs) {
                if(item.startsWith("token")) {
                    token = item.substring(item.indexOf("=") + 1);
                }
            }
            if(null == token) {
                throw new ResponseStatusException(BAD_REQUEST, NO_TOKEN);
            }
            byte[] rv = ObjStorageService.getDocumentForToken(token).getBytes();
            DocumentMetadataDTO typeForToken = ObjStorageService.getTypeForToken(token);
            response.setContentType(typeForToken.getMimetype());
            if((typeForToken.getMimetype().equals("application/pdf"))) {
                response.setHeader("Content-Disposition", "inline; filename=" + typeForToken.getFilename());
            } else {
                response.setHeader("Content-Disposition", "attachment; filename=" + typeForToken.getFilename());
            }
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Cache-Control", "no-cache");
            response.getOutputStream().write(rv);
        } catch (ObjectStorageService.InvalidTokenException | IOException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(BAD_REQUEST, ex.getMessage());
        } catch (ObjectStorageService.InvalidKeyConfigException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR);
        }
    }
    @GetMapping(value="/getMetadataForToken")
    public DocumentMetadataDTO getMetadataForToken(@RequestParam("token") String token) {
        try {
            return ObjStorageService.getTypeForToken(token);
        } catch (ObjectStorageService.InvalidTokenException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(BAD_REQUEST, ex.getMessage());
        } catch (ObjectStorageService.InvalidKeyConfigException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(value = "/getDataToSignMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public DataToSignDTO getDataToSignMultiple(@RequestBody GetDataToSignMultipleDTO dataToSignDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(dataToSignDto.getSigningProfileId(), dataToSignDto.getClientSignatureParameters());

            ToBeSignedDTO dataToSign = signatureServiceMultiple.getDataToSign(dataToSignDto.getToSignDocuments(), parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            return new DataToSignDTO(digestAlgorithm, DSSUtils.digest(digestAlgorithm, dataToSign.getBytes()));
        } catch (ProfileNotFoundException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/signDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocument(@RequestBody SignDocumentDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureService.signDocument(signDocumentDto.getToSignDocument(), parameters, signatureValueDto);

            return validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents());
        } catch (ProfileNotFoundException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }
    
    @PostMapping(value = "/signDocumentForToken", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentForToken(@RequestBody SignDocumentForTokenDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(ObjStorageService.getProfileForToken(signDocumentDto.getToken()), signDocumentDto.getClientSignatureParameters());
            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureService.signDocument(ObjStorageService.getDocumentForToken(signDocumentDto.getToken(), 60 * 5), parameters, signatureValueDto);
            signedDoc.setName(ObjStorageService.getTypeForToken(signDocumentDto.getToken()).getFilename());

            signedDoc = validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents());
            ObjStorageService.storeDocumentForToken(signDocumentDto.getToken(), signedDoc);

            return signedDoc;
        } catch (JOSEException | ParseException | ProfileNotFoundException
                | NullParameterException
                | ObjectStorageService.InvalidTokenException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(BAD_REQUEST, ex.getMessage());
        } catch (InvalidKeyConfigException ex) {
            Logger.getLogger(SigningController.class.getName()).log(Level.SEVERE, null, ex);
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(value = "/signDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument signDocumentMultiple(@RequestBody SignDocumentMultipleDTO signDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getSignatureParams(signDocumentDto.getSigningProfileId(), signDocumentDto.getClientSignatureParameters());

            SignatureValueDTO signatureValueDto = new SignatureValueDTO(parameters.getSignatureAlgorithm(), signDocumentDto.getSignatureValue());
            RemoteDocument signedDoc = signatureServiceMultiple.signDocument(signDocumentDto.getToSignDocuments(), parameters, signatureValueDto);

            return validateResult(signedDoc, signDocumentDto.getClientSignatureParameters().getDetachedContents());
        } catch (ProfileNotFoundException | NullParameterException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/extendDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocument(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = signatureService.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            return validateResult(extendedDoc, extendDocumentDto.getDetachedContents());
        } catch (ProfileNotFoundException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/extendDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument extendDocumentMultiple(@RequestBody ExtendDocumentDTO extendDocumentDto) {
        try {
            RemoteSignatureParameters parameters = signingConfigService.getExtensionParams(extendDocumentDto.getExtendProfileId(), extendDocumentDto.getDetachedContents());

            RemoteDocument extendedDoc = signatureServiceMultiple.extendDocument(extendDocumentDto.getToExtendDocument(), parameters);

            return validateResult(extendedDoc, extendDocumentDto.getDetachedContents());
        } catch (ProfileNotFoundException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/timestampDocument", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocument(@RequestBody TimestampDocumentDTO timestampDocumentDto) {
        try {
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            return signatureService.timestamp(timestampDocumentDto.getDocument(), parameters);
        } catch (ProfileNotFoundException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping(value = "/timestampDocumentMultiple", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public RemoteDocument timestampDocumentMultiple(@RequestBody TimestampDocumentMultipleDTO timestampDocumentDto) {
        try {
            RemoteTimestampParameters parameters = signingConfigService.getTimestampParams(timestampDocumentDto.getProfileId());

            return signatureServiceMultiple.timestamp(timestampDocumentDto.getDocuments(), parameters);
        } catch (ProfileNotFoundException e) {
            throw new ResponseStatusException(BAD_REQUEST, e.getMessage());
        }
    }

    private RemoteDocument validateResult(RemoteDocument signedDoc, List<RemoteDocument> detachedContents) {
        WSReportsDTO reportsDto = validationService.validateDocument(signedDoc, detachedContents, null);
        SignatureIndicationsDTO indications = reportsService.getSignatureIndicationsDto(reportsDto);

        if (indications.getIndication() == TOTAL_PASSED) {
            return signedDoc;
        } else {
            String subIndication = indications.getSubIndication();
            String mesg = (subIndication.equals(CERT_REVOKED)) ? CERT_REVOKED :
                String.format("Signed document did not pass validation: %s, %s", indications.getIndication(), subIndication);
            throw new ResponseStatusException(BAD_REQUEST, mesg);
        }
    }

    private void checkDataToSign(ClientSignatureParameters clientSigParams) throws ResponseStatusException {
        // Check signing date
        Date now = new Date();
        Calendar oldest = Calendar.getInstance();
        oldest.setTime(now);
        oldest.add(Calendar.MINUTE, -5);
        Calendar newest = Calendar.getInstance();
        newest.setTime(now);
        newest.add(Calendar.MINUTE, 5);
        Date d = clientSigParams.getSigningDate();
        if(newest.before(d) || oldest.after(d)) {
            throw new ResponseStatusException(BAD_REQUEST, INVALID_SIG_DATE);
        }

        // Check if the signing cert is present and not expired
        try {
        RemoteCertificate signingCert = clientSigParams.getSigningCertificate();
        if (null == signingCert)
            throw new ResponseStatusException(BAD_REQUEST, NO_SIGN_CERT);
        byte[] signingCertBytes = signingCert.getEncodedCertificate();
        if (null == signingCertBytes)
            throw new ResponseStatusException(BAD_REQUEST, NO_SIGN_CERT);
        X509Certificate signingCrt = (X509Certificate) CertificateFactory.getInstance("X509")
            .generateCertificate(new ByteArrayInputStream(signingCertBytes));
        if (now.after(signingCrt.getNotAfter()))
            throw new ResponseStatusException(BAD_REQUEST, SIGN_CERT_EXPIRED);
        }
        catch (CertificateException e) {
            throw new ResponseStatusException(BAD_REQUEST, "error parsing signing certificate: " + e.getMessage());
        }

        // Check if the cert chain is present (at least 2 certs)
        List<RemoteCertificate> chain = clientSigParams.getCertificateChain();
        if (null == chain || chain.size() < 2)
            throw new ResponseStatusException(BAD_REQUEST, CERT_CHAIN_INCOMPLETE);
    }
}
