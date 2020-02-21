package com.zetes.projects.bosa.signandvalidation.controller;

import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
@RequestMapping(value = "/validation")
public class ValidationController {

    @Autowired
    RemoteDocumentValidationService remoteDocumentValidationService;

    @Autowired
    RemoteCertificateValidationService remoteCertificateValidationService;

    @GetMapping(value = "/ping", produces = TEXT_PLAIN_VALUE)
    public String ping() {
        return "pong";
    }

    @PostMapping(value = "/validateSignature", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public WSReportsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) {
        return remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());
    }

    @PostMapping(value = "/validateCertificate", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateReportsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        return remoteCertificateValidationService.validateCertificate(toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime());
    }

}
