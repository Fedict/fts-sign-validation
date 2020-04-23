package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.SignAndValidationTestBase;
import com.zetes.projects.bosa.signandvalidation.model.SignatureIndicationsDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.*;
import static org.junit.jupiter.api.Assertions.*;
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
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndication());
    }

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void signatureWithTotalFailedFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_nok.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(SIG_CRYPTO_FAILURE, result.getSubIndication());
    }

    @Disabled("Temporary pipeline disable") // TODO
    @Test
    public void signatureWithNoPolicyAndNoOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/XAdESLTA.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(NO_POE, result.getSubIndication());
    }

    @Test
    public void signatureWithNoPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
    }

    @Test
    public void signatureWithNoPolicyAndDigestOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        FileDocument fileDocument = new FileDocument("src/test/resources/sample.xml");
        RemoteDocument originalFile = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileDocument), fileDocument.getName());
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
    }

    @Test
    public void signatureWithPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, policy);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
    }

    @Test
    public void signatureWithPolicyAndNoOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, policy);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
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
