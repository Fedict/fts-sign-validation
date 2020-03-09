package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.IndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.model.IndicationsListDTO;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/validation")
public class ValidationController {

    @Autowired
    private RemoteDocumentValidationService remoteDocumentValidationService;

    @Autowired
    private RemoteCertificateValidationService remoteCertificateValidationService;

    @Autowired
    private ReportsService reportsService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = "/validateSignature", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public WSReportsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) {
        if (toValidate.getSignedDocument() != null) {
            return remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());
        } else {
            throw new ResponseStatusException(BAD_REQUEST, "DSSDocument is null");
        }
    }

    @PostMapping(value = "/validateCertificate", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateReportsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        if (toValidate.getCertificate() != null) {
            return remoteCertificateValidationService.validateCertificate(toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime());
        } else {
            throw new ResponseStatusException(BAD_REQUEST, "The certificate is missing");
        }
    }

    @PostMapping(value = "/validateCertificates", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public IndicationsListDTO validateCertificates(@RequestBody List<CertificateToValidateDTO> toValidateList) {
        List<IndicationsDTO> indications = new ArrayList<>();

        for (CertificateToValidateDTO toValidate : toValidateList) {
            CertificateReportsDTO certificateReportsDTO = validateCertificate(toValidate);
            indications.add(reportsService.getIndicationsDTO(certificateReportsDTO));
        }

        return new IndicationsListDTO(indications);
    }

}
