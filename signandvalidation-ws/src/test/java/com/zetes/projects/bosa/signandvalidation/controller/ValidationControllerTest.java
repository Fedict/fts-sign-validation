package com.zetes.projects.bosa.signandvalidation.controller;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ValidationControllerTest extends SignAndValidationTestBase {

    @Test
    public void pingShouldReturnPong() throws Exception {
        // when
        String result = this.restTemplate.getForObject("http://localhost:" + port + "/validation/ping", String.class);

        // then
        assertEquals("pong", result);
    }

    @Test
    public void testWithTotalPassedFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_ok.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

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

    @Test
    public void testWithTotalFailedFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_nok.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

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
    public void testWithNoPolicyAndNoOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/XAdESLTA.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(2, result.getDiagnosticData().getSignatures().get(0).getFoundTimestamps().size());
        assertEquals(result.getSimpleReport().getSignature().get(0).getIndication(), Indication.INDETERMINATE);

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void testWithNoPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void testWithNoPolicyAndDigestOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        FileDocument fileDocument = new FileDocument("src/test/resources/sample.xml");
        RemoteDocument originalFile = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileDocument), fileDocument.getName());
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void testWithPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, policy);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void testWithPolicyAndNoOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, policy);

        // when
        WSReportsDTO result = this.restTemplate.postForObject("http://localhost:" + port + "/validation/validateSignature", toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignature().size());
        assertEquals(result.getSimpleReport().getSignature().get(0).getIndication(), Indication.INDETERMINATE);

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

}
