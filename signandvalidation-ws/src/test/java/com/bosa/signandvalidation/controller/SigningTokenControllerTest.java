package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signandvalidation.service.StorageService;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

public class SigningTokenControllerTest extends SigningControllerBaseTest {

    private static final String THE_BUCKET = "ZeBucket";

    @MockBean
    private StorageService storageService;

    // Warning : Unit tests are running with a fixed "hardcoded" time.
    @Value("${signing.time}")
    private Long signingTime;

    @Test
    public void testSigningTimeNOK() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);

        File inFile = new File("src/test/resources/sample.pdf");
        byte[] fileBytes = Utils.toByteArray(new FileInputStream(inFile));
        Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(inFile.getName()), eq(true))).thenReturn(fileBytes);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.PADES_B.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());

        // GetDataToSignForToken (With 10 second timeout)
        getTokenDTO.setSignTimeout(10);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // Set time of GetDataToSignForToken 11 seconds ago
        clientSignatureParameters.setSigningDate(new Date(signingTime - 11000));
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());

        // sign document
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, Map.class);
        assertNotNull(result);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().contains(SIGN_PERIOD_EXPIRED));
    }

    @Test
    public void testSigningNotAllowedNN() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);

        File inFile = new File("src/test/resources/sample.pdf");
        byte[] fileBytes = Utils.toByteArray(new FileInputStream(inFile));
        Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(inFile.getName()), eq(true))).thenReturn(fileBytes);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.PADES_B.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        List<AllowedToSign> signers = new ArrayList<>();
        signers.add(new AllowedToSign("12345678901"));
        getTokenDTO.setAllowedToSign(signers);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, Map.class);
        assertNotNull(result);

        assertEquals(INTERNAL_SERVER_ERROR.value(), result.get("status"));
        assert(result.get("message").toString().contains(NOT_ALLOWED_TO_SIGN));
    }

    @Test
    public void testSigningTimeOK() throws Exception {
        Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

        File inFile = new File("src/test/resources/sample.xml");
        byte[] fileBytes = Utils.toByteArray(new FileInputStream(inFile));
        Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(inFile.getName()), eq(true))).thenReturn(fileBytes);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.XADES_B.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        getTokenDTO.setSignTimeout(1000);
        getTokenDTO.setNoDownload(false);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, RemoteDocument.class);
        assertNull(signedDocument);
    }

    @Test
    public void testSigningDetachedProfile() throws Exception {
        Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

        File inFile = new File("src/test/resources/sample.xml");
        byte[] fileBytes = Utils.toByteArray(new FileInputStream(inFile));
        Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(inFile.getName()), eq(true))).thenReturn(fileBytes);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.XADES_B_DETACHED.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        getTokenDTO.setSignTimeout(1000);
        getTokenDTO.setNoDownload(false);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT + SigningController.SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, RemoteDocument.class);
        assertNull(signedDocument);
    }
}
