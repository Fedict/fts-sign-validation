package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.StorageService;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;

import static com.zetes.projects.bosa.signandvalidation.controller.SigningController.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class SigningTokenControllerTest extends SigningControllerBaseTest {

    private static final String THE_BUCKET = "ZeBucket";

    @MockBean
    private StorageService storageService;

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
        getTokenDTO.setProf("PADES_B");
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        getTokenDTO.setSignTimeout(0);
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, "non, rien !", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, clientSignatureParameters, signatureValue.getValue());
        Map result = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, Map.class);
        assertNotNull(result);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().contains(SIGN_PERIOD_EXPIRED));
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
        getTokenDTO.setProf("XADES_B");
        getTokenDTO.setName(THE_BUCKET);
        getTokenDTO.setIn(inFile.getName());
        getTokenDTO.setSignTimeout(1000);
        getTokenDTO.setNoDownload(false);
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_TOKEN_FOR_DOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, "non, rien !", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + GET_DATA_TO_SIGN_FOR_TOKEN, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + ENDPOINT + SIGN_DOCUMENT_FOR_TOKEN, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);
    }
}
