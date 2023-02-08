package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.SignAndValidationTestBase;
import com.bosa.signandvalidation.config.ErrorStrings;
import com.bosa.signandvalidation.model.CertificateIndicationsDTO;
import com.bosa.signandvalidation.model.CertificateToValidateDTO;
import com.bosa.signandvalidation.model.IndicationsListDTO;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static eu.europa.esig.dss.enumerations.Indication.INDETERMINATE;
import static eu.europa.esig.dss.enumerations.Indication.PASSED;
import static eu.europa.esig.dss.enumerations.KeyUsageBit.KEY_CERT_SIGN;
import static eu.europa.esig.dss.enumerations.KeyUsageBit.NON_REPUDIATION;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class ValidateCertificatesTest extends SignAndValidationTestBase implements ErrorStrings {

    public static final String CERTIFICATE_ENDPOINT = "/validation/validateCertificate";
    public static final String CERTIFICATEFULL_ENDPOINT = "/validation/validateCertificateFull";
    public static final String CERTIFICATES_ENDPOINT = "/validation/validateCertificates";

    @Test
    public void certificatePassed() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        // given
        RemoteCertificate passedCertificate = getPassedCertificate();
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(passedCertificate, null, null, NON_REPUDIATION);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertEquals("Christian TestLongNames", indicationsDTO.getCommonName());
        assertEquals(PASSED, indicationsDTO.getIndication());
        assertNull(indicationsDTO.getSubIndication());
    }

    @Test
    public void certificateIndeterminate() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        // given
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(getExpiredIssuingCACertificateInstanceCert(),
                Collections.singletonList(getExpiredIssuingCACertificate()), null, NON_REPUDIATION);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertEquals("FredWith IssuingCACertExpired", indicationsDTO.getCommonName());
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
        assert(result.get("message").toString().endsWith(NO_CERT_TO_VALIDATE + "||"));
    }

    @Test
    public void certificateKeyUsageOk() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        // given
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(getExpiredIssuingCACertificateInstanceCert(),
                null, null, NON_REPUDIATION);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assert(indicationsDTO.isKeyUsageCheckOk());
    }

    @Test
    public void certificateKeyUsageNok() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        // given
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(getExpiredIssuingCACertificateInstanceCert(),
                null, null, KEY_CERT_SIGN);

        // when
        CertificateIndicationsDTO indicationsDTO = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATE_ENDPOINT, toValidate, CertificateIndicationsDTO.class);

        // then
        assertFalse(indicationsDTO.isKeyUsageCheckOk());
    }

    @Test
    public void certificateFull() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        // given
        CertificateToValidateDTO toValidate = new CertificateToValidateDTO(getExpiredIssuingCACertificateInstanceCert(),
                Collections.singletonList(getExpiredIssuingCACertificate()), null, NON_REPUDIATION);

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
    public void certificatesPassedAndIndeterminate() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        // given
        List<CertificateToValidateDTO> toValidateList = new ArrayList<>();
        toValidateList.add(new CertificateToValidateDTO(getPassedCertificate(), null, null, NON_REPUDIATION));
        toValidateList.add(new CertificateToValidateDTO(getExpiredIssuingCACertificateInstanceCert(),
                Collections.singletonList(getExpiredIssuingCACertificate()), null, NON_REPUDIATION));

        // when
        IndicationsListDTO result = this.restTemplate.postForObject(LOCALHOST + port + CERTIFICATES_ENDPOINT, toValidateList, IndicationsListDTO.class);

        // then
        assertNotNull(result.getIndications());
        assertEquals(2, result.getIndications().size());

        assertEquals("Christian TestLongNames", result.getIndications().get(0).getCommonName());
        assertEquals(PASSED, result.getIndications().get(0).getIndication());
        assertNull(result.getIndications().get(0).getSubIndication());
        assertTrue(result.getIndications().get(0).isKeyUsageCheckOk());

        assertEquals("FredWith IssuingCACertExpired", result.getIndications().get(1).getCommonName());
        assertEquals(INDETERMINATE, result.getIndications().get(1).getIndication());
        assertNotNull(result.getIndications().get(1).getSubIndication());
        assertTrue(result.getIndications().get(1).isKeyUsageCheckOk());
    }

    private static Map<String, KeyStore> keyStores = new HashMap<>();

    private KeyStore getKeyStore(String keyFileName) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore keyStore = keyStores.get(keyFileName);
        if (keyStore == null) {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("src/test/resources/" + keyFileName), "123456".toCharArray());
            keyStores.put(keyFileName, keyStore);
        }
        return keyStore;
    }

    private RemoteCertificate getPassedCertificate() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        return RemoteCertificateConverter.toRemoteCertificate(new CertificateToken((X509Certificate) getKeyStore("citizen_nonrep.p12").getCertificate("test")));
    }

    private RemoteCertificate getExpiredIssuingCACertificateInstanceCert() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        //return RemoteCertificateConverter.toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CZ.cer")));
        return RemoteCertificateConverter.toRemoteCertificate(new CertificateToken((X509Certificate) getKeyStore("expiredIssuingCa_citizen.p12").getCertificate("test")));
    }

    private RemoteCertificate getExpiredIssuingCACertificate() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        //return RemoteCertificateConverter.toRemoteCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA_CZ.cer")));
        return RemoteCertificateConverter.toRemoteCertificate(new CertificateToken((X509Certificate) getKeyStore("expiredIssuingCa_citizen.p12").getCertificateChain("test")[1]));
    }
}
