package com.zetes.projects.bosa.signandvalidation.controller;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ValidationControllerTest extends SignAndValidationTestBase {

    public static final String LOCALHOST = "http://localhost:";
    public static final String SIGNATURE_ENDPOINT = "/validation/validateSignature";
    public static final String CERTIFICATE_ENDPOINT = "/validation/validateCertificate";

    @Test
    public void pingShouldReturnPong() throws Exception {
        // when
        String result = this.restTemplate.getForObject(LOCALHOST + port + "/validation/ping", String.class);

        // then
        assertEquals("pong", result);
    }

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
        assertEquals(result.getSimpleReport().getSignature().get(0).getIndication(), Indication.INDETERMINATE);

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
        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

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
        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

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
        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignature().get(0).getIndication());

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
        assertEquals(result.getSimpleReport().getSignature().get(0).getIndication(), Indication.INDETERMINATE);

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void certificateWithCertificateChainAndValidationTime() {
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));
        Calendar calendar = Calendar.getInstance();
        calendar.set(2018, 12, 31);
        Date validationDate = calendar.getTime();
        validationDate.setTime((validationDate.getTime() / 1000) * 1000); // clean millis
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                Arrays.asList(issuerCertificate), validationDate);

        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateReportsDTO.class);

        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
        assertEquals(3, usedCertificates.size());
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertEquals(3, chain.size());
        for (XmlCertificate certificate : usedCertificates) {
            if (chain.get(0).getId().equals(certificate.getId())) {
                assertEquals(2, certificate.getCertificateChain().size());
            }
        }
        assertEquals(0, validationDate.compareTo(diagnosticData.getValidationDate()));
    }

    @Test
    public void certificateWithNoValidationTime() {
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));

        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                Arrays.asList(issuerCertificate), null);

        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateReportsDTO.class);

        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
        assertEquals(3, usedCertificates.size());
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertEquals(3, chain.size());
        for (XmlCertificate certificate : usedCertificates) {
            if (chain.get(0).getId().equals(certificate.getId())) {
                assertEquals(2, certificate.getCertificateChain().size());
            }
        }
        assertNotNull(diagnosticData.getValidationDate());
    }

    @Test
    public void certificateWithNoCertificateChain() {
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate);

        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateReportsDTO.class);

        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
        assertEquals(3, usedCertificates.size());
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertEquals(3, chain.size());
        for (XmlCertificate certificate : usedCertificates) {
            if (chain.get(0).getId().equals(certificate.getId())) {
                assertEquals(2, certificate.getCertificateChain().size());
            }
        }
        assertNotNull(diagnosticData.getValidationDate());
    }

}
