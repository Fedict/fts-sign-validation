package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import com.bosa.signandvalidation.service.StorageService;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
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

        File inFile = mockGetFile("src/test/resources/sample.pdf");

        Pkcs12SignatureToken token = getSignatureToken();
        DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKeys().get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.PADES_B.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());

        // GetDataToSignForToken (With 10 second timeout)
        getTokenDTO.setSignTimeout(10);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_TOKEN_FOR_DOCUMENT_URL, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN_URL, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // Set time of GetDataToSignForToken 11 seconds ago
        clientSignatureParameters.setSigningDate(new Date(signingTime - 11000));
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());

        // sign document
        Map result = signSocumentAndWaitForResult(signDocumentDTO, Map.class);
        assertNotNull(result);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().contains(SIGN_PERIOD_EXPIRED));
    }

    @Test
    public void testSigningNotAllowedNN() throws Exception {
        Mockito.when(storageService.isValidAuth(any(),any())).thenReturn(true);

        File inFile = mockGetFile("src/test/resources/sample.pdf");

        Pkcs12SignatureToken token = getSignatureToken();
        DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKeys().get(0);

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
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_TOKEN_FOR_DOCUMENT_URL, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN_URL, dataToSignDTO, Map.class);
        assertNotNull(result);

        assertEquals(INTERNAL_SERVER_ERROR.value(), result.get("status"));
        assert(result.get("message").toString().contains(NOT_ALLOWED_TO_SIGN));
    }

    @Test
    public void testSigningTimeOK() throws Exception {
        Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

        File inFile = mockGetFile("src/test/resources/sample.xml");

        Pkcs12SignatureToken token = getSignatureToken();
        DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKeys().get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.XADES_B.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        getTokenDTO.setSignTimeout(1000);
        getTokenDTO.setNoDownload(false);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_TOKEN_FOR_DOCUMENT_URL, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN_URL, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());
        Object noResult = signSocumentAndWaitForResult(signDocumentDTO, Map.class);
        assertNull(noResult);
    }

    @Test
    public void testSigningDetachedProfile() throws Exception {
        Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

        File inFile = mockGetFile("src/test/resources/sample.xml");

        Pkcs12SignatureToken token = getSignatureToken();
        DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKeys().get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        getTokenDTO.setProf(SignProfiles.XADES_B_DETACHED.name());
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        getTokenDTO.setSignTimeout(1000);
        getTokenDTO.setNoDownload(false);
        getTokenDTO.setOut("out");
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_TOKEN_FOR_DOCUMENT_URL, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN_URL, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());
        Object noResult = signSocumentAndWaitForResult(signDocumentDTO, Map.class);
        assertNull(noResult);
    }

    private static String OUT_FILENAME = "out";
    private static String OID_URI = "urn:oid:1.3.6.1.4.1.35390.10.8.7.1.0";

    @Test
    public void testSigningMultifileDetachedProfile() throws Exception {
        Mockito.when(storageService.isValidAuth(any(), any())).thenReturn(true);

        File inFile1 = mockGetFile("src/test/resources/sample.xml");
        File inFile2 = mockGetFile("src/test/resources/sample.pdf");

        Pkcs12SignatureToken token = getSignatureToken();
        DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKeys().get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        List<SignInput> inFiles = new ArrayList<>(2);
        inFiles.add(new SignInput(inFile1.getName(), null, OID_URI, null, null, null, null, null, false, false));
        inFiles.add(new SignInput(inFile2.getName(), null, null, null, null, null, null, null, false, false));
        GetTokenForDocumentsDTO gtfd = new GetTokenForDocumentsDTO(THE_BUCKET, "pwd", SignProfiles.XADES_MULTIFILE_DETACHED.name(), inFiles, OUT_FILENAME);
        gtfd.setOutDownload(true);

        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_TOKEN_FOR_DOCUMENTS_URL, gtfd, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, 0, clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + SigningController.ENDPOINT_URL + SigningController.GET_DATA_TO_SIGN_FOR_TOKEN_URL, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, 0, clientSignatureParameters, signatureValue.getValue());

        Object noResult = signSocumentAndWaitForResult(signDocumentDTO, Object.class);
        assertNull(noResult);

        ArgumentCaptor<byte[]> fileBytesCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(storageService).storeFile(Mockito.eq(THE_BUCKET), Mockito.eq(OUT_FILENAME), fileBytesCaptor.capture());

        String outputXades = new String(fileBytesCaptor.getValue());
        System.out.println(outputXades);

        assertTrue(outputXades.contains("URI=\"" + URLEncoder.encode(OID_URI) + "\""));
        assertTrue(outputXades.contains("URI=\"" + inFile2.getName() + "\""));
    }

    private Pkcs12SignatureToken getSignatureToken() throws IOException {
        return new Pkcs12SignatureToken(
                Files.newInputStream(Paths.get("src/test/resources/citizen_nonrep.p12")),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
    }

    private File mockGetFile(String path) throws IOException {
        File inFile = new File(path);
        byte[] fileBytes = Utils.toByteArray(Files.newInputStream(inFile.toPath()));
        Mockito.when(storageService.getFileAsBytes(eq(THE_BUCKET), eq(inFile.getName()), eq(true))).thenReturn(fileBytes);
        return inFile;
    }
}
