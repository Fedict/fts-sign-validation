package com.zetes.projects.bosa.signandvalidation.controller;

import com.zetes.projects.bosa.signandvalidation.TokenParser;
import com.zetes.projects.bosa.signandvalidation.model.*;
import com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService;
import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class SigningTokenControllerTest extends SigningControllerBaseTest {

    private static final String THE_PROFILE = "PADES_B";
    @Mock
    private TokenParser fakeTP;

    private static final String THE_TOKEN = "TheToken";
    @MockBean
    private ObjectStorageService ObjStorageService;

    public static final String GETTOKENFORDOCUMENT = "/signing/getTokenForDocument";
    public static final String GETDATATOSIGNFORTOKEN_ENDPOINT = "/signing/getDataToSignForToken";
    public static final String SIGNDOCUMENTFORTOKEN_ENDPOINT = "/signing/signDocumentForToken";

    @Test
    public void testSigningTimeNOK() throws Exception {
        Mockito.reset(fakeTP, ObjStorageService);
        Mockito.when(fakeTP.isAllowedToSignCheckNeeded()).thenReturn(false);
        Mockito.when(fakeTP.getProf()).thenReturn(THE_PROFILE);
        Mockito.when(fakeTP.getSignTimeout()).thenReturn(0);           // Set impossible timeout

        Mockito.when(ObjStorageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(ObjStorageService.getTokenForDocument(any())).thenReturn("TheToken");
        Mockito.when(ObjStorageService.parseToken(eq(THE_TOKEN), anyInt())).thenReturn(fakeTP);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

        Mockito.when(ObjStorageService.getDocumentForToken(eq(fakeTP), eq(false))).thenReturn(toSignDocument);


        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + GETTOKENFORDOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, "non, rien !", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGNFORTOKEN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, clientSignatureParameters, signatureValue.getValue());
        Map result = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENTFORTOKEN_ENDPOINT, signDocumentDTO, Map.class);
        assertNotNull(result);

        assertEquals(BAD_REQUEST.value(), result.get("status"));
        assert(result.get("message").toString().contains(SIGN_PERIOD_EXPIRED));
    }

    @Test
    public void testSigningTimeOK() throws Exception {
        Mockito.reset(fakeTP, ObjStorageService);
        Mockito.when(fakeTP.isAllowedToSignCheckNeeded()).thenReturn(false);
        Mockito.when(fakeTP.getProf()).thenReturn(THE_PROFILE);
        Mockito.when(fakeTP.getSignTimeout()).thenReturn(1000);       // Set OK timeout

        Mockito.when(ObjStorageService.isValidAuth(any(),any())).thenReturn(true);
        Mockito.when(ObjStorageService.getTokenForDocument(any())).thenReturn("TheToken");
        Mockito.when(ObjStorageService.parseToken(eq(THE_TOKEN), anyInt())).thenReturn(fakeTP);
        Mockito.when(ObjStorageService.getProfileForToken(eq(fakeTP))).thenReturn(THE_PROFILE);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
        Mockito.when(ObjStorageService.getDocumentForToken(eq(fakeTP), eq(false))).thenReturn(toSignDocument);

        DocumentMetadataDTO documentMetadataDTO = new DocumentMetadataDTO("out.pdf", "application/pdf", null, false, true, false);
        Mockito.when(ObjStorageService.getTypeForToken(eq(fakeTP))).thenReturn(documentMetadataDTO);

        Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new FileInputStream("src/test/resources/citizen_nonrep.p12"),
                new KeyStore.PasswordProtection("123456".toCharArray())
        );
        List<DSSPrivateKeyEntry> keys = token.getKeys();
        DSSPrivateKeyEntry dssPrivateKeyEntry = keys.get(0);

        ClientSignatureParameters clientSignatureParameters = getClientSignatureParameters(dssPrivateKeyEntry);

        // get token from file
        GetTokenForDocumentDTO getTokenDTO = new GetTokenForDocumentDTO();
        String tokenStr = this.restTemplate.postForObject(LOCALHOST + port + GETTOKENFORDOCUMENT, getTokenDTO, String.class);

        // get data to sign
        GetDataToSignForTokenDTO dataToSignDTO = new GetDataToSignForTokenDTO(tokenStr, "non, rien !", clientSignatureParameters);
        DataToSignDTO dataToSign = this.restTemplate.postForObject(LOCALHOST + port + GETDATATOSIGNFORTOKEN_ENDPOINT, dataToSignDTO, DataToSignDTO.class);

        // sign
        SignatureValue signatureValue = token.signDigest(new Digest(dataToSign.getDigestAlgorithm(), dataToSign.getDigest()), dssPrivateKeyEntry);

        // sign document
        clientSignatureParameters.setSigningDate(dataToSign.getSigningDate());
        SignDocumentForTokenDTO signDocumentDTO = new SignDocumentForTokenDTO(tokenStr, clientSignatureParameters, signatureValue.getValue());
        RemoteDocument signedDocument = this.restTemplate.postForObject(LOCALHOST + port + SIGNDOCUMENTFORTOKEN_ENDPOINT, signDocumentDTO, RemoteDocument.class);
        assertNotNull(signedDocument);
    }
}
