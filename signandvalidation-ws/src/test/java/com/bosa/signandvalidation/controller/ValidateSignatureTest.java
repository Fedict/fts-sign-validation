package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.SignAndValidationTestBase;
import com.bosa.signandvalidation.model.DataToValidateDTO;
import com.bosa.signandvalidation.model.SignatureIndicationsDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.CRYPTO_CONSTRAINTS_FAILURE;
import static eu.europa.esig.dss.enumerations.SubIndication.HASH_FAILURE;
import static eu.europa.esig.dss.enumerations.SubIndication.SIGNED_DATA_NOT_FOUND;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import com.bosa.signandvalidation.config.ErrorStrings;

public class ValidateSignatureTest extends SignAndValidationTestBase implements ErrorStrings {

    public static final String SIGNATURE_ENDPOINT = "/validation/validateSignature";
    public static final String SIGNATUREFULL_ENDPOINT = "/validation/validateSignatureFull";

    @Test
    public void signatureB() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_b.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndicationLabel());
    }

    @Test
    public void signatureT() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_t.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_T);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndicationLabel());
    }

    @Test
    public void signatureLT() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_lt.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_LT);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndicationLabel());
    }

    @Test
    public void signatureLTA() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_lta.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_LTA);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndicationLabel());
    }


    @Test
    public void signatureLT_LTA_ExpectsLT() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_lt-lta.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_LT);

        // when
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, Map.class);

        // then
        assertNotNull(result);
        assertTrue(((String)result.get("message")).contains(INVALID_SIGNATURE_LEVEL));
    }

    @Test
    public void signatureBexpectsLTA() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_b.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_LTA);

        // when
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, Map.class);

        // then
        assertNotNull(result);
        assertTrue(((String)result.get("message")).contains(INVALID_SIGNATURE_LEVEL));
    }

    @Test
    public void signaturePadesLTA() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/pades-lta.pdf"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.PAdES_BASELINE_LTA);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithUnsigedFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(SIGNED_DATA_NOT_FOUND.toString(), result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithNoPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(HASH_FAILURE.toString(), result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithNoPolicyAndDigestOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        FileDocument fileDocument = new FileDocument("src/test/resources/sample.xml");
        RemoteDocument originalFile = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileDocument), fileDocument.getName());
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(HASH_FAILURE.toString(), result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithPolicyAndOriginalFile() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/main/resources/policy/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, policy);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(HASH_FAILURE.toString(), result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithNoFileProvided() {
        // given
        DataToValidateDTO toValidate = new DataToValidateDTO();
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, Map.class);

        // then
        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().endsWith(NO_DOC_TO_VALIDATE + "||"));
    }

    @Test
    public void signatureFullWithNoPolicyAndOriginalFile() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_b.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        WSReportsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATUREFULL_ENDPOINT, toValidate, WSReportsDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getSimpleReport().getSignatureOrTimestamp().size());
        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(),
                result.getValidationReport());
        assertNotNull(reports);
    }

    @Test
    public void signatureSHA1() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_b_sha1.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(CRYPTO_CONSTRAINTS_FAILURE.toString(), result.getSubIndicationLabel());
    }

}
