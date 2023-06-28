package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.SignAndValidationTestBase;
import com.bosa.signandvalidation.model.DataToValidateDTO;
import com.bosa.signandvalidation.model.SignatureFullValiationDTO;
import com.bosa.signandvalidation.model.SignatureIndicationsDTO;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import com.bosa.signandvalidation.config.ErrorStrings;

public class ValidateSignatureTest extends SignAndValidationTestBase implements ErrorStrings {

    public static final String SIGNATURE_ENDPOINT = "/validation/validateSignature";
    public static final String SIGNATUREFULL_ENDPOINT = "/validation/validateSignatureFull";

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
        assertNull(result.getSubIndicationLabel());
        assertEquals(TOTAL_PASSED, result.getIndication());
    }

    @Test
    // As unit tests don't include OCSP the revocation freshness has to be set to large timespans which make testing a "real life" case impossible
    // This test tries to at least confirm the particular behavior of the BRCA3 validation policy
    public void validateBRCA3() {
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/BRCA3.pdf"));
        RemoteDocument defaultPolicy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/main/resources/policy/constraint.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setPolicy(defaultPolicy);

        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        assertNotNull(result);
        // Temporary change for BRCA3 exception as now even the BRCA4 Policy will allow BRCA3 signatures
        // TODO : Change when a final solution is available for Revocation Freshness issues
        //assertEquals(TRY_LATER.toString(), result.getSubIndicationLabel());
        //assertEquals(INDETERMINATE, result.getIndication());
        assertNull(result.getSubIndicationLabel());
        assertEquals(TOTAL_PASSED, result.getIndication());

        RemoteDocument brca3Policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/policy/BRCA3_constraint_test.xml"));
        toValidate = new DataToValidateDTO(signedFile);
        toValidate.setPolicy(brca3Policy);

        result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        assertNotNull(result);
        assertNull(result.getSubIndicationLabel());
        assertEquals(TOTAL_PASSED, result.getIndication());
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
    public void signatureWithUnsigedFile() {
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
    public void signatureWithNoPolicyAndOriginalFile() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(HASH_FAILURE.toString(), result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithNoPolicyAndDigestOriginalFile() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        FileDocument fileDocument = new FileDocument("src/test/resources/sample.xml");
        RemoteDocument originalFile = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileDocument), fileDocument.getName());
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(HASH_FAILURE.toString(), result.getSubIndicationLabel());
    }

    @Test
    public void signatureWithPolicyAndOriginalFile() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
        RemoteDocument originalFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sample.xml"));
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/policy/constraint.xml"));
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
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureFullValiationDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATUREFULL_ENDPOINT, toValidate, SignatureFullValiationDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());

        assertEquals(1, result.getSimpleReport().getSignatureOrTimestamp().size());
    }

    @Test
    public void signatureSHA1() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_b_sha1.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.XAdES_BASELINE_B);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_FAILED, result.getIndication());
        assertEquals(CRYPTO_CONSTRAINTS_FAILURE.toString(), result.getSubIndicationLabel());
    }




}
