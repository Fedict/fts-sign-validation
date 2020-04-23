package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.model.CertificateToValidateDTO;
import com.zetes.projects.bosa.signandvalidation.model.IndicationsListDTO;
import com.zetes.projects.bosa.signandvalidation.model.SignatureIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.service.ReportsService;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
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
    public SignatureIndicationsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) {
        if (toValidate.getSignedDocument() != null) {
            WSReportsDTO reportsDto = remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy());

            return reportsService.getSignatureIndicationsDto(reportsDto);
        } else {
            throw new ResponseStatusException(BAD_REQUEST, "DSSDocument is null");
        }
    }

    @PostMapping(value = "/validateCertificate", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public CertificateIndicationsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        if (toValidate.getCertificate() != null) {
            CertificateReportsDTO certificateReportsDTO = remoteCertificateValidationService.validateCertificate(toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime());
            return reportsService.getCertificateIndicationsDTO(certificateReportsDTO, toValidate.getExpectedKeyUsage());
        } else {
            throw new ResponseStatusException(BAD_REQUEST, "The certificate is missing");
        }
    }

    @PostMapping(value = "/validateCertificates", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public IndicationsListDTO validateCertificates(@RequestBody List<CertificateToValidateDTO> toValidateList) {
        List<CertificateIndicationsDTO> indications = new ArrayList<>();

        for (CertificateToValidateDTO toValidate : toValidateList) {
            indications.add(validateCertificate(toValidate));
        }

        return new IndicationsListDTO(indications);
    }

}
