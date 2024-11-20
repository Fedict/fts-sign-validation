package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.SignAndValidationBaseTest;
import com.bosa.signandvalidation.model.*;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Map;

import static eu.europa.esig.dss.enumerations.Indication.*;
import static eu.europa.esig.dss.enumerations.SubIndication.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import com.bosa.signandvalidation.config.ErrorStrings;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

public class ValidateSignatureTest extends SignAndValidationBaseTest implements ErrorStrings {

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
    public void validateBRCA3() {
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/BRCA3.pdf"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);

        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        assertEquals(INDETERMINATE, result.getIndication());
        assertEquals(CERT_REVOKED, result.getSubIndicationLabel());
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

        assertEquals(1, result.getSimpleReport().getSignatureOrTimestampOrEvidenceRecord().size());
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

    @Test
    public void signatureWithExtraTrust() throws IOException {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/Foreign_trust_signed.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
        TrustSources ksc = new TrustSources();
        toValidate.setTrust(ksc);
        ksc.setCerts(new ArrayList<>());
        ksc.getCerts().add(Files.readAllBytes(Paths.get("src/test/resources/extra_trust.der")));

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
    }

    @Test
    public void detailedReportRegressionTest() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/pades-lta.pdf"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.PAdES_BASELINE_LTA);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());

        File schemaFile = new File("src/test/resources/DetailedReport.xsd");

        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = schemaFactory.newSchema(schemaFile);
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(new StringReader(result.getReport())));
    }

    /* The only file signed with a non BE signature is a production document, this test is therefore stripped from the test suite
    @Test
    public void validateBE_nonBETest() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/BE_nonBE.pdf"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(SignatureLevel.PAdES_BASELINE_LTA);

        // when
        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATURE_ENDPOINT, toValidate, SignatureIndicationsDTO.class);

        // then
        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
    }

    private static String replace(String start, String end, String src, String dst) {
        int pos = src.indexOf(start) + start.length();
        int endPos = src.indexOf(end, pos + 1);
        String value = src.substring(pos, endPos);
        pos = dst.indexOf(start) + start.length();
        endPos = dst.indexOf(end, pos + 1);
        return dst.replaceAll(dst.substring(pos, endPos), value);
    }
 */
}
