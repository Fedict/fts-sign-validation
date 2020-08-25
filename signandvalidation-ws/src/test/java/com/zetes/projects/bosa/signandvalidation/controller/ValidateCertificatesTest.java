package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import com.zetes.projects.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.model.CertificateToValidateDTO;
import com.zetes.projects.bosa.signandvalidation.model.IndicationsListDTO;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.*;

import static eu.europa.esig.dss.enumerations.Indication.INDETERMINATE;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static eu.europa.esig.dss.enumerations.KeyUsageBit.KEY_CERT_SIGN;
import static eu.europa.esig.dss.enumerations.KeyUsageBit.NON_REPUDIATION;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class ValidateCertificatesTest extends SignAndValidationTestBase {

    public static final String CERTIFICATE_ENDPOINT = "/validation/validateCertificate";
    public static final String CERTIFICATEFULL_ENDPOINT = "/validation/validateCertificateFull";
    public static final String CERTIFICATES_ENDPOINT = "/validation/validateCertificates";

    @Test
    public void certificatePassed() {
        // given
        RemoteCertificate passedCertificate = getPassedCertificate();
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(passedCertificate, null, null, NON_REPUDIATION);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertEquals("TestSign CitizenCA", indicationsDTO.getCommonName());
        assertEquals(PASSED, indicationsDTO.getIndication());
        assertNull(indicationsDTO.getSubIndication());
    }

    @Test
    public void certificateIndeterminate() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));

        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                Arrays.asList(issuerCertificate), null, NON_REPUDIATION);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertEquals("Rostislav Šaler", indicationsDTO.getCommonName());
        assertEquals(INDETERMINATE, indicationsDTO.getIndication());
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

    @Test
    public void certificateKeyUsageOk() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));

        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                null, null, NON_REPUDIATION);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertTrue(indicationsDTO.isKeyUsageCheckOk());
    }

    @Test
    public void certificateKeyUsageNok() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));

        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                null, null, KEY_CERT_SIGN);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertFalse(indicationsDTO.isKeyUsageCheckOk());
    }

    @Test
    public void certificateFull() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));

        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(remoteCertificate,
                Arrays.asList(issuerCertificate), null, NON_REPUDIATION);

        // when
        CertificateReportsDTO reportsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATEFULL_ENDPOINT, toValidate, CertificateReportsDTO.class);

        // then
        assertNotNull(reportsDTO.getDiagnosticData());
        assertNotNull(reportsDTO.getSimpleCertificateReport());
        assertNotNull(reportsDTO.getDetailedReport());

        XmlDiagnosticData xmlDiagnosticData = reportsDTO.getDiagnosticData();
        List<XmlCertificate> usedCertificates = xmlDiagnosticData.getUsedCertificates();
        assertTrue(usedCertificates.size() > 1);
        List<XmlChainItem> chain = reportsDTO.getSimpleCertificateReport().getChain();
        assertTrue(chain.size() > 1);

        DiagnosticData diagnosticData = new DiagnosticData(xmlDiagnosticData);
        assertNotNull(diagnosticData);

        for (XmlChainItem chainItem : chain) {
            CertificateWrapper certificate = diagnosticData.getUsedCertificateById(chainItem.getId());
            assertNotNull(certificate);
            CertificateWrapper signingCertificate = certificate.getSigningCertificate();
        }
    }

    @Test
    public void certificatesPassedAndIndeterminate() {
        // given
        RemoteCertificate passedCertificate = getPassedCertificate();
        CertificateToValidateDTO passedToValidate = new CertificateToValidateDTO(passedCertificate, null, null, NON_REPUDIATION);

        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));
        CertificateToValidateDTO indeterminateToValidate = new CertificateToValidateDTO(remoteCertificate,
                Collections.singletonList(issuerCertificate), null, NON_REPUDIATION);

        List<CertificateToValidateDTO> toValidateList = new ArrayList<>();
        toValidateList.add(passedToValidate);
        toValidateList.add(indeterminateToValidate);

        // when
        IndicationsListDTO result = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATES_ENDPOINT, toValidateList, IndicationsListDTO.class);

        // then
        assertNotNull(result.getIndications());
        assertEquals(2, result.getIndications().size());

        assertEquals("TestSign CitizenCA", result.getIndications().get(0).getCommonName());
        assertEquals(PASSED, result.getIndications().get(0).getIndication());
        assertNull(result.getIndications().get(0).getSubIndication());
        assertFalse(result.getIndications().get(0).isKeyUsageCheckOk());

        assertEquals("Rostislav Šaler", result.getIndications().get(1).getCommonName());
        assertEquals(INDETERMINATE, result.getIndications().get(1).getIndication());
        assertNotNull(result.getIndications().get(1).getSubIndication());
        assertTrue(result.getIndications().get(1).isKeyUsageCheckOk());
    }

    private RemoteCertificate getPassedCertificate() {
        return RemoteCertificateConverter.toRemoteCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDEzCCApigAwIBAgIRAIrCwoVCOYzX1jIQz06ouBAwCgYIKoZIzj0EAwMwMTELMAkGA1UEBhMCQkUxIjAgBgNVBAMMGVRlc3RTaWduIEJlbGdpdW0gUm9vdCBDQTYwHhcNMjAwMTE1MTQzMTM0WhcNMzIwMTE1MTQzMTM0WjBYMQswCQYDVQQGEwJCRTEbMBkGA1UECgwSQmVsZ2lhbiBHb3Zlcm5tZW50MRswGQYDVQQDDBJUZXN0U2lnbiBDaXRpemVuQ0ExDzANBgNVBAUTBjIwMjAwMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABPnhhrdIIgz9aDKyMBkJOU1siv1nTs6OCx01ABYki83RwWJ9/i5Q5/hi7042x5Wc3VEinodQl2QIWAE4eARj9vU0sUlVROe+voMi6G6YO5FT1xMjJ6jN7C6XghV6/AG4vqOCAUswggFHMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMEBggrBgEFBQcDAjAdBgNVHQ4EFgQUNhf7FN+hDfg+bJG9lMFaQ/3JkWAwHwYDVR0jBBgwFoAU3fBCho6noAuRtkDCNTbZxbBBWj4wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2hvbWUuc2NhcmxldC5iZS9zdGgvYnJjYTYuY3JsMEAGCCsGAQUFBwEBBDQwMjAwBggrBgEFBQcwAoYkaHR0cDovL2hvbWUuc2NhcmxldC5iZS9zdGgvYnJjYTYuY3J0MEkGA1UdIARCMEAwPgYEVR0gADA2MDQGCCsGAQUFBwIBFihodHRwczovL3JlcG9zaXRvcnkuZWlkcGtpLmJlbGdpdW0uYmUvZWlkMAoGCCqGSM49BAMDA2kAMGYCMQDutMmYelV3c9VDfEXx1KX9bu+1ATZibYu7wqo/B9r/nDs1ASN5OPR39/vEQ4eEodsCMQDu2fDqxlASFhwR1MMp/MDAbdIFTYmih+Q1gQasRZ5k6LOf9MeT3wUH8Lexi9Ruh8I="));
    }

}
