package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import com.zetes.projects.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.zetes.projects.bosa.signandvalidation.model.CertificateToValidateDTO;
import com.zetes.projects.bosa.signandvalidation.model.IndicationsListDTO;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static eu.europa.esig.dss.enumerations.Indication.INDETERMINATE;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static eu.europa.esig.dss.enumerations.KeyUsageBit.KEY_CERT_SIGN;
import static eu.europa.esig.dss.enumerations.KeyUsageBit.NON_REPUDIATION;
import static eu.europa.esig.dss.enumerations.SubIndication.OUT_OF_BOUNDS_NO_POE;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class ValidateCertificatesTest extends SignAndValidationTestBase {

    public static final String CERTIFICATE_ENDPOINT = "/validation/validateCertificate";
    public static final String CERTIFICATES_ENDPOINT = "/validation/validateCertificates";

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
        assertEquals(OUT_OF_BOUNDS_NO_POE, indicationsDTO.getSubIndication());
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

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void certificatesWithPassedAndIndeterminateCertificates() {
        // given
        RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(
                DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        RemoteCertificate issuerCertificate = RemoteCertificateConverter
                .toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));

        List<CertificateToValidateDTO> toValidateList = new ArrayList<>();
        toValidateList.add(new CertificateToValidateDTO(remoteCertificate, null, null, NON_REPUDIATION));
        toValidateList.add(new CertificateToValidateDTO(issuerCertificate, null, null, KEY_CERT_SIGN));

        // when
        IndicationsListDTO result = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATES_ENDPOINT, toValidateList, IndicationsListDTO.class);

        // then
        assertNotNull(result.getIndications());
        assertEquals(2, result.getIndications().size());
        assertEquals("Rostislav Šaler", result.getIndications().get(0).getCommonName());
        assertEquals(INDETERMINATE, result.getIndications().get(0).getIndication());
        assertEquals(OUT_OF_BOUNDS_NO_POE, result.getIndications().get(0).getSubIndication());
        assertTrue(result.getIndications().get(0).isKeyUsageCheckOk());
        assertEquals("I.CA - Qualified Certification Authority, 09/2009", result.getIndications().get(1).getCommonName());
        assertEquals(PASSED, result.getIndications().get(1).getIndication());
        assertNull(result.getIndications().get(1).getSubIndication());
        assertTrue(result.getIndications().get(1).isKeyUsageCheckOk());
    }

}
