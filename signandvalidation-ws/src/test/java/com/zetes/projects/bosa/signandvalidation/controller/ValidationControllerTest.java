package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.IndicationsListDTO;
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
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.*;

import static eu.europa.esig.dss.enumerations.Indication.INDETERMINATE;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static eu.europa.esig.dss.enumerations.SubIndication.OUT_OF_BOUNDS_NO_POE;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class ValidationControllerTest extends SignAndValidationTestBase {

    public static final String SIGNATURE_ENDPOINT = "/validation/validateSignature";
    public static final String CERTIFICATE_ENDPOINT = "/validation/validateCertificate";
    public static final String CERTIFICATES_ENDPOINT = "/validation/validateCertificates";

    @Test
    public void pingShouldReturnPong() throws Exception {
        // when
        String result = this.restTemplate.getForObject(LOCALHOST + port + "/validation/ping", String.class);

        // then
        assertEquals("pong", result);
    }

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

    @Test
    public void certificateWithCertificateChainAndValidationTime() {
        // given
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

        // when
        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateReportsDTO.class);

        // then
        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
        assertTrue(usedCertificates.size() > 1, "usedCertificates.size() > 1");
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertTrue(chain.size() > 1, "chain.size() > 1");
        for (XmlCertificate certificate : usedCertificates) {
            if (chain.get(0).getId().equals(certificate.getId())) {
                assertTrue(certificate.getCertificateChain().size() > 0, "certificate.getCertificateChain().size() > 0");
            }
        }
        assertEquals(0, validationDate.compareTo(diagnosticData.getValidationDate()));
    }

    @Test
    public void certificateWithNoValidationTime() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));

        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                Arrays.asList(issuerCertificate), null);

        // when
        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateReportsDTO.class);

        // then
        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
        assertTrue(usedCertificates.size() > 1, "usedCertificates.size() > 1");
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertTrue(chain.size() > 1, "chain.size() > 1");
        for (XmlCertificate certificate : usedCertificates) {
            if (chain.get(0).getId().equals(certificate.getId())) {
                assertTrue(certificate.getCertificateChain().size() > 0, "certificate.getCertificateChain().size() > 0");
            }
        }
        assertNotNull(diagnosticData.getValidationDate());
    }

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void certificateWithNoCertificateChain() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate);

        // when
        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateReportsDTO.class);

        // then
        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData diagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = diagnosticData.getUsedCertificates();
        assertTrue(usedCertificates.size() > 1, "usedCertificates.size() > 1");
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertTrue(chain.size() > 1, "chain.size() > 1");
        for (XmlCertificate certificate : usedCertificates) {
            if (chain.get(0).getId().equals(certificate.getId())) {
                assertTrue(certificate.getCertificateChain().size() > 0, "certificate.getCertificateChain().size() > 0");
            }
        }
        assertNotNull(diagnosticData.getValidationDate());
    }

    @Test
    public void certificateWithNoCertificateProvided() {
        // given
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO();

        // when
        Map result = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, Map.class);

        // then
        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assertEquals("The certificate is missing", result.get("message"));
    }

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void certificatesWithPassedAndIndeterminateCertificates() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));

        List<CertificateToValidateDTO> toValidateList = new ArrayList<>();
        toValidateList.add(new CertificateToValidateDTO(remoteCertificate, null, null));
        toValidateList.add(new CertificateToValidateDTO(issuerCertificate, null, null));

        // when
        IndicationsListDTO result = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATES_ENDPOINT, toValidateList, IndicationsListDTO.class);

        // then
        assertNotNull(result.getIndications());
        assertEquals(2, result.getIndications().size());
        assertEquals(INDETERMINATE, result.getIndications().get(0).getIndication());
        assertEquals(OUT_OF_BOUNDS_NO_POE, result.getIndications().get(0).getSubIndication());
        assertEquals(PASSED, result.getIndications().get(1).getIndication());
    }

}
