package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;

import static com.bosa.signandvalidation.controller.SigningController.*;
import static eu.europa.esig.dss.enumerations.Indication.TOTAL_PASSED;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class SigningControllerTest extends SigningControllerBaseTest {

    @Test
    public void testSigningAndExtensionXades() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_B", clientSignatureParameters, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + GET_DATA_TO_SIGN_URL, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "XADES_B", clientSignatureParameters, signatureValue.getValue(), null, "ID");
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + SIGN_DOCUMENT_URL, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        // extend document
        ExtendDocumentDTO extendDocumentDTO = new ExtendDocumentDTO(signedDocument, "XADES_T", null, "ID");
        RemoteDocument extendedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + EXTEND_DOCUMENT_URL, extendDocumentDTO, RemoteDocument.class);
        assertNotNull(extendedDocument);

        InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
        iMD.save("target/test.xml");
    }

    @Test
    public void testSigningCades() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "CADES_B", clientSignatureParameters, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + GET_DATA_TO_SIGN_URL, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "CADES_B", clientSignatureParameters, signatureValue.getValue(), null, "ID");
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + SIGN_DOCUMENT_URL, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        iMD.save("target/test.zip");
    }

    @Test
    public void testSigningPades() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "PADES_B", clientSignatureParameters, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + GET_DATA_TO_SIGN_URL, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "PADES_B", clientSignatureParameters, signatureValue.getValue(), null, "ID");
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + SIGN_DOCUMENT_URL, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        iMD.save("target/test.pdf");
    }

    @Test
    public void testSigningJades() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.json"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "JADES_B", clientSignatureParameters, "ID");
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + GET_DATA_TO_SIGN_URL, dataToSignDTO, DataToSignDTO.class);
        assertNotNull(dataToSign);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentDTO signDocumentDTO = new SignDocumentDTO(toSignDocument, "JADES_B", clientSignatureParameters, signatureValue.getValue(), null, "ID");
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + SIGN_DOCUMENT_URL, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);

        DataToValidateDTO toValidate = new DataToValidateDTO(signedDocument);
        toValidate.setLevel(SignatureLevel.JAdES_BASELINE_B);

        SignatureIndicationsDTO result = this.restTemplate.postForObject(LOCALHOST + port + "/validation/validateSignature", toValidate, SignatureIndicationsDTO.class);

        assertNotNull(result);
        assertEquals(TOTAL_PASSED, result.getIndication());
        assertNull(result.getSubIndicationLabel());

        System.out.println("Jades signature : " + new String(signedDocument.getBytes()));
    }

    @Test
    public void testTimestampPdf() {
        FileDocument fileToTimestamp = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument remoteDocument = RemoteDocumentConverter.toRemoteDocument(fileToTimestamp);

        TimestampDocumentDTO timestampOneDocumentDTO = new TimestampDocumentDTO(remoteDocument, "PROFILE_1", "ID");
        RemoteDocument timestampedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + TIMESTAMP_DOCUMENT_URL, timestampOneDocumentDTO, RemoteDocument.class);

        assertNotNull(timestampedDocument);

        InMemoryDocument iMD = new InMemoryDocument(timestampedDocument.getBytes());
        // iMD.save("target/testSigned.pdf");
        assertNotNull(iMD);
    }

    @Test
    public void testExpired() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/expired.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_B", clientSignatureParameters, "ID");
        Map result = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + GET_DATA_TO_SIGN_URL, dataToSignDTO, Map.class);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().contains(SIGN_CERT_EXPIRED + "||exp. date = 2021.03.06"));
    }

    @Test
    public void testNoChain() throws Exception {
        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/nochain.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        // get data to sign
        GetDataToSignDTO dataToSignDTO = new GetDataToSignDTO(toSignDocument, "XADES_B", clientSignatureParameters, "ID");
        Map result = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT_URL + GET_DATA_TO_SIGN_URL, dataToSignDTO, Map.class);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().endsWith("CERT_CHAIN_INCOMPLETE" + "||cert count: 1"));
    }
}
