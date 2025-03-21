package com.bosa.signandvalidation.service;

import com.bosa.signandvalidation.config.ThreadDataCleaner;
import com.bosa.signandvalidation.exceptions.IllegalSignatureFormatException;
import com.bosa.signandvalidation.model.*;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.bosa.signandvalidation.config.ErrorStrings.*;
import static com.bosa.signandvalidation.exceptions.Utils.checkAndRecordMDCToken;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Service
public class ValidationService {

    private static final String VALIDATION_CONSTRAINTS = "validateCertificateConstraint.xml";

    protected final Logger logger = Logger.getLogger(ValidationService.class.getName());

    @Autowired
    private BosaRemoteDocumentValidationService remoteDocumentValidationService;

    @Autowired
    private RemoteCertificateValidationService remoteCertificateValidationService;

    @Autowired
    private ReportsService reportsService;

    //*****************************************************************************************

    public SignatureIndicationsDTO validateSignature(@RequestBody DataToValidateDTO toValidate) throws IOException {
        checkAndRecordMDCToken(toValidate.getToken());
        SignatureFullValiationDTO report = validateSignatureFull(toValidate);
        SignatureIndicationsDTO signDto = reportsService.getSignatureIndicationsAndReportsDto(report);
        logger.info("ValidateSignature is finished");
        return signDto;
    }

    //*****************************************************************************************

    @Async("asyncTasks")
    public Future<Object> validateSignatureASync(DataToValidateDTO toValidate) {
        CompletableFuture<Object> task = new CompletableFuture<>();
        try {
            task.complete(validateSignature(toValidate));
        } catch(Exception e){
            task.completeExceptionally(e);
        } finally {
            // We're on a different thread (ASYNC) so clear all thread data
            ThreadDataCleaner.clearAll();
        }
        return task;
    }

    //*****************************************************************************************

    public SignatureFullValiationDTO validateSignatureFull(@RequestBody DataToValidateDTO toValidate) {
        checkAndRecordMDCToken(toValidate.getToken());
        if (toValidate.getSignedDocument() == null)
            logAndThrowEx(BAD_REQUEST, NO_DOC_TO_VALIDATE, null, null);
        try {
            SignatureFullValiationDTO reportsDto = remoteDocumentValidationService.validateDocument(toValidate.getSignedDocument(), toValidate.getOriginalDocuments(), toValidate.getPolicy(), toValidate.getTrust());
            if (toValidate.getLevel() != null && reportsDto.getDiagnosticData() != null) {
                checkSignatures(toValidate.getLevel().toDSS(), reportsDto);
            }
            logger.info("ValidateSignatureFull is finished");
            return reportsDto;
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        } catch (IllegalSignatureFormatException e) {
            logAndThrowEx(BAD_REQUEST, INVALID_SIGNATURE_LEVEL, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    private void checkSignatures(SignatureLevel level, SignatureFullValiationDTO reportsDto) throws IllegalSignatureFormatException {
        List<XmlSignature> signatures = reportsDto.getDiagnosticData().getSignatures();
        if (signatures != null)  {
            for (XmlSignature signature : signatures) {
                if (!level.equals(signature.getSignatureFormat())) {
                    throw new IllegalSignatureFormatException("Was : " + signature.getSignatureFormat() + ", expected :" + level);
                }
            }
        }
    }

    //*****************************************************************************************

    public CertificateIndicationsDTO validateCertificate(@RequestBody CertificateToValidateDTO toValidate) {
        checkAndRecordMDCToken(toValidate.getToken());
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            // Use a custom validation constraint because Belgian eID (BRCA3/BRCA4) are still using SHA1 in the cert chain
            InputStream genericIs = ValidationService.class.getResourceAsStream("/policy/" + VALIDATION_CONSTRAINTS);
            RemoteDocument policy = new RemoteDocument(Utils.toByteArray(genericIs), VALIDATION_CONSTRAINTS);
            eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO dto = new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
                    toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime());
            dto.setPolicy(policy);

            CertificateReportsDTO certificateReportsDTO = remoteCertificateValidationService.validateCertificate(dto);
            CertificateIndicationsDTO rv = reportsService.getCertificateIndicationsDTO(certificateReportsDTO, toValidate.getExpectedKeyUsage());
            if(rv.getIndication() != PASSED) {
                certificateReportsDTO.getSimpleCertificateReport().getChain().forEach(item -> {
                    logger.log(Level.SEVERE, "Certificate validation indication = {0}; certificate ID = {1}, issuer ID = {2}", new Object[]{rv.getIndication().toString(), item.getId(), item.getIssuerId()});
                });
            }
            logger.info("ValidateCertificate is finished");
            return rv;
        } catch (RuntimeException | IOException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public CertificateFullValidationDTO validateCertificateFull(@RequestBody CertificateToValidateDTO toValidate) {
        checkAndRecordMDCToken(toValidate.getToken());
        if (toValidate.getCertificate() == null)
            logAndThrowEx(BAD_REQUEST, NO_CERT_TO_VALIDATE, null, null);

        try {
            CertificateReportsDTO result = remoteCertificateValidationService.validateCertificate(
                new eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO(
			        toValidate.getCertificate(), toValidate.getCertificateChain(), toValidate.getValidationTime()));
            logger.info("ValidateCertificateFull is finished");

            return new CertificateFullValidationDTO(result.getDiagnosticData(), result.getSimpleCertificateReport(), result.getDetailedReport());
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************

    public IndicationsListDTO validateCertificates(@RequestBody List<CertificateToValidateDTO> toValidateList) {
        try {
            List<CertificateIndicationsDTO> indications = new ArrayList<>();

            for (CertificateToValidateDTO toValidate : toValidateList) {
                indications.add(validateCertificate(toValidate));
            }

            logger.info("ValidateCertificates is finished");
            return new IndicationsListDTO(indications);
        } catch (RuntimeException e) {
            logAndThrowEx(INTERNAL_SERVER_ERROR, INTERNAL_ERR, e);
        }
        return null; // We won't get here
    }

    //*****************************************************************************************
}
