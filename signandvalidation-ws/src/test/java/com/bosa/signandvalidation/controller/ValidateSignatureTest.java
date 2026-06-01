package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.SignAndValidationBaseTest;
import com.bosa.signandvalidation.model.*;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Map;

import static com.bosa.signandvalidation.model.SignatureLevel.*;
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
        toValidate.setLevel(XAdES_BASELINE_LT);

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
        toValidate.setLevel(XAdES_BASELINE_LTA);

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

        assertEquals(TOTAL_PASSED, result.getIndication());
    }

    @Test
    public void signatureLT_LTA_ExpectsLT() {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/signed_lt-lta.xml"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(XAdES_BASELINE_LT);

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
        toValidate.setLevel(XAdES_BASELINE_LTA);

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
        toValidate.setLevel(PAdES_BASELINE_LTA);

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
        toValidate.setLevel(XAdES_BASELINE_B);

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
        toValidate.setLevel(XAdES_BASELINE_B);

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
        toValidate.setLevel(XAdES_BASELINE_B);

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
        toValidate.setLevel(XAdES_BASELINE_B);

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
        toValidate.setLevel(XAdES_BASELINE_B);

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
        toValidate.setLevel(XAdES_BASELINE_B);

        // when
        SignatureFullValiationDTO result = this.restTemplate.postForObject(LOCALHOST + port + SIGNATUREFULL_ENDPOINT, toValidate, SignatureFullValiationDTO.class);

        // then
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());

        assertEquals(1, result.getSimpleReport().getSignatureOrTimestampOrEvidenceRecord().size());
    }

    @Test
    public void signatureSHA1() throws FileNotFoundException {
        // given

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray()));

        DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
        parameters.setSigningCertificate(privateKey.getCertificate());
        parameters.setCertificateChain(privateKey.getCertificateChain());

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(verifier);

        FileDocument toSignDocument = new FileDocument(new File("src/test/resources/sample.xml"));
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
        SignatureValue signatureValue = token.sign(dataToSign, DigestAlgorithm.SHA1, privateKey);

        DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(signedDocument);
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);
        toValidate.setLevel(XAdES_BASELINE_B);

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
        // TODO As the signing cert (or chert chain) expired we need to create a new test input
        assertTrue(TOTAL_PASSED.equals(result.getIndication()) || INDETERMINATE.equals(result.getIndication()));
    }

    @Test
    public void detailedReportRegressionTest() throws Exception {
        // given
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/pades-lta.pdf"));
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile);
        toValidate.setLevel(PAdES_BASELINE_LTA);

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
