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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
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

import java.util.Date;
import java.util.List;

import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import java.io.IOException;
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
public class SigningController {

    @Autowired
    private SigningConfiguratorService signingConfigService;

    @Autowired
    private RemoteDocumentSignatureService signatureService;

    @Autowired
    private RemoteMultipleDocumentsSignatureService signatureServiceMultiple;

    @Autowired
    private RemoteDocumentValidationService validationService;

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
            Calendar oldest = Calendar.getInstance();
            oldest.setTime(new Date());
            oldest.add(-5, Calendar.MINUTE);
            Calendar newest = Calendar.getInstance();
            newest.setTime(new Date());
            newest.add(5, Calendar.MINUTE);
            Date d = dataToSignDto.getClientSignatureParameters().getSigningDate();
            if(newest.before(d) || oldest.after(d)) {
                throw new ResponseStatusException(BAD_REQUEST, "signing date out of bounds");
            }
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
            Calendar oldest = Calendar.getInstance();
            oldest.setTime(new Date());
            oldest.add(-5, Calendar.MINUTE);
            Calendar newest = Calendar.getInstance();
            newest.setTime(new Date());
            newest.add(5, Calendar.MINUTE);
            Date d = dataToSignForTokenDto.getClientSignatureParameters().getSigningDate();
            if(newest.before(d) || oldest.after(d)) {
                throw new ResponseStatusException(BAD_REQUEST, "signing date out of bounds");
            }
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
                throw new ResponseStatusException(FORBIDDEN, "invalid user name or password");
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
                throw new ResponseStatusException(BAD_REQUEST, "Required parameter token not provided");
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
            throw new ResponseStatusException(BAD_REQUEST,
                    String.format("Signed document did not pass validation: %s, %s", indications.getIndication(), indications.getSubIndication())
            );
        }
    }

}
