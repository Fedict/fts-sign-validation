package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static eu.europa.esig.dss.enumerations.Indication.INDETERMINATE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class ValidateSignatureTest extends SignAndValidationTestBase {

    public static final String SIGNATURE_ENDPOINT = "/validation/validateSignature";

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void signatureWithTotalPassedFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_ok.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(0, result.getDiagnosticData().getSignatures().get(0).getFoundTimestamps().size());
        assertEquals(Indication.TOTAL_PASSED, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void signatureWithTotalFailedFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_nok.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(0, result.getDiagnosticData().getSignatures().get(0).getFoundTimestamps().size());
        assertEquals(Indication.TOTAL_FAILED, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureWithNoPolicyAndNoOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/XAdESLTA.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(2, result.getDiagnosticData().getSignatures().get(0).getFoundTimestamps().size());
        assertEquals(result.getSimpleReport().getSignature().get(0).getIndication(), INDETERMINATE);

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureWithNoPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureWithNoPolicyAndDigestOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        FileDocument fileDocument = new FileDocument("src/test/resources/sample.xml");
        RemoteDocument originalFile = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileDocument), fileDocument.getName());
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureWithPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, policy);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureWithPolicyAndNoOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, policy);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(result.getSimpleReport().getSignature().get(0).getIndication(), INDETERMINATE);

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureWithNoFileProvided() {
        // given
        DataToValidateDTO toValidate = new DataToValidateDTO();

        // when
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, Map.class);

        // then
        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assertEquals("DSSDocument is null", result.get("message"));
    }

}
