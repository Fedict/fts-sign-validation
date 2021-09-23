package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.model.CertificateToValidateDTO;
import com.zetes.projects.bosa.signandvalidation.model.IndicationsListDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignatureIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import com.zetes.projects.bosa.signandvalidation.service.BosaRemoteDocumentValidationService;
import com.zetes.projects.bosa.signandvalidation.config.ErrorStrings;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/validation")
public class ValidationController extends ControllerBase implements ErrorStrings {

    @Autowired
    private BosaRemoteDocumentValidationService remoteDocumentValidationService;

    @Autowired
    private RemoteCertificateValidationService remoteCertificateValidationService;

    @Autowired
    private ReportsService reportsService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = "/validateSignature", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public SignatureIndicationsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) {
        if (toValidate.getSignedDocument() == null)
            logAndThrowEx(BAD_REQUEST, NO_DOC_TO_VALIDATE, null, null);

        try {
            WSReportsDTO reportsDto = remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());
            return reportsService.getSignatureIndicationsDto(reportsDto);
	} catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/validateSignatureFull", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public WSReportsDTO validateSignatureFull(@RequestBody DataToValidateDTO toValidate) {
        if (toValidate.getSignedDocument() == null)
            logAndThrowEx(BAD_REQUEST, NO_DOC_TO_VALIDATE, null, null);

        try {
            return remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/validateCertificate", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateIndicationsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            CertificateReportsDTO certificateReportsDTO = remoteCertificateValidationService.validateCertificate(
                new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
			toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
            CertificateIndicationsDTO rv = reportsService.getCertificateIndicationsDTO(certificateReportsDTO, toValidate.getExpectedKeyUsage());
            if(rv.getIndication() != PASSED) {
                certificateReportsDTO.getSimpleCertificateReport().getChain().forEach(item -> {
                    logger.log(Level.SEVERE, "Certificate validation indication = {0}; certificate ID = {1}, issuer ID = {2}", new Object[]{rv.getIndication().toString(), item.getId(), item.getIssuerId()});
                });
            }
            return rv;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/validateCertificateFull", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateReportsDTO validateCertificateFull(@RequestBody CertificateToValidateDTO toValidate) {
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            return remoteCertificateValidationService.validateCertificate(
                new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
			toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    @PostMapping(value = "/validateCertificates", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public IndicationsListDTO validateCertificates(@RequestBody List<CertificateToValidateDTO> toValidateList) {
        try {
            List<CertificateIndicationsDTO> indications = new ArrayList<>();

            for (CertificateToValidateDTO toValidate : toValidateList) {
                indications.add(validateCertificate(toValidate));
            }

        return new IndicationsListDTO(indications);
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }
}
